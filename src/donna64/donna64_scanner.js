/**
 * donna64_scanner.js - Fast wallet scanning using donna64 optimized crypto
 * 
 * This module provides a high-performance interface to the donna64 elliptic
 * curve operations for scanning Salvium blockchain transactions.
 * 
 * Expected performance: 10-14x faster than ref10 implementation
 * - ref10 generate_key_derivation: ~7ms per TX
 * - donna64 generate_key_derivation: ~0.5ms per TX
 */

class Donna64Scanner {
    constructor(wasmModule) {
        this.module = wasmModule;
        this._initialized = false;
        
        // Wrap the C functions
        this._fastGenerateKeyDerivation = null;
        this._fastBatchKeyDerivations = null;
        this._donna64Benchmark = null;
        
        // Reusable memory buffers for reduced allocation overhead
        this._derivationPtr = null;
        this._txPubPtr = null;
        this._viewSecPtr = null;
        
        // Batch processing buffers
        this._batchDerivationsPtr = null;
        this._batchTxPubsPtr = null;
        this._batchSize = 0;
    }
    
    /**
     * Initialize the scanner - must be called after WASM module is ready
     */
    async init() {
        if (this._initialized) return;
        
        // Check donna64 availability
        const version = this.module._donna64_get_version();
        if (!version) {
            throw new Error('donna64 not available in WASM module');
        }
        console.log(`donna64 initialized, version: ${(version >> 16)}.${(version >> 8) & 0xFF}.${version & 0xFF}`);
        
        // Create function wrappers
        this._fastGenerateKeyDerivation = this.module.cwrap('fast_generate_key_derivation', 
            'number', ['number', 'number', 'number']);
        this._fastBatchKeyDerivations = this.module.cwrap('fast_batch_key_derivations',
            'number', ['number', 'number', 'number', 'number']);
        this._donna64Benchmark = this.module.cwrap('donna64_benchmark',
            'number', ['number']);
        
        // Allocate reusable single-operation buffers (32 bytes each)
        this._derivationPtr = this.module._malloc(32);
        this._txPubPtr = this.module._malloc(32);
        this._viewSecPtr = this.module._malloc(32);
        
        if (!this._derivationPtr || !this._txPubPtr || !this._viewSecPtr) {
            throw new Error('Failed to allocate WASM memory for donna64');
        }
        
        this._initialized = true;
    }
    
    /**
     * Clean up allocated memory
     */
    destroy() {
        if (this._derivationPtr) this.module._free(this._derivationPtr);
        if (this._txPubPtr) this.module._free(this._txPubPtr);
        if (this._viewSecPtr) this.module._free(this._viewSecPtr);
        if (this._batchDerivationsPtr) this.module._free(this._batchDerivationsPtr);
        if (this._batchTxPubsPtr) this.module._free(this._batchTxPubsPtr);
        
        this._derivationPtr = null;
        this._txPubPtr = null;
        this._viewSecPtr = null;
        this._batchDerivationsPtr = null;
        this._batchTxPubsPtr = null;
        this._initialized = false;
    }
    
    /**
     * Set the view secret key (call once, reused for all derivations)
     * @param {Uint8Array|string} viewSecKey - 32-byte view secret key (hex string or Uint8Array)
     */
    setViewSecretKey(viewSecKey) {
        if (!this._initialized) throw new Error('Scanner not initialized');
        
        const bytes = typeof viewSecKey === 'string' 
            ? this._hexToBytes(viewSecKey) 
            : viewSecKey;
            
        if (bytes.length !== 32) {
            throw new Error(`View secret key must be 32 bytes, got ${bytes.length}`);
        }
        
        this.module.HEAPU8.set(bytes, this._viewSecPtr);
    }
    
    /**
     * Generate key derivation for a single transaction
     * @param {Uint8Array|string} txPubKey - 32-byte transaction public key
     * @returns {Uint8Array|null} - 32-byte derivation, or null if tx_pub is invalid
     */
    generateKeyDerivation(txPubKey) {
        if (!this._initialized) throw new Error('Scanner not initialized');
        
        const bytes = typeof txPubKey === 'string' 
            ? this._hexToBytes(txPubKey) 
            : txPubKey;
            
        if (bytes.length !== 32) {
            throw new Error(`TX public key must be 32 bytes, got ${bytes.length}`);
        }
        
        // Copy tx_pub to WASM memory
        this.module.HEAPU8.set(bytes, this._txPubPtr);
        
        // Call donna64 fast derivation
        const result = this._fastGenerateKeyDerivation(
            this._derivationPtr, 
            this._txPubPtr, 
            this._viewSecPtr
        );
        
        if (result !== 1) {
            return null; // Invalid point
        }
        
        // Copy result back
        return new Uint8Array(this.module.HEAPU8.buffer, this._derivationPtr, 32).slice();
    }
    
    /**
     * Generate key derivation and return as hex string
     * @param {string} txPubKeyHex - 64-character hex string
     * @returns {string|null} - 64-character hex derivation, or null if invalid
     */
    generateKeyDerivationHex(txPubKeyHex) {
        const result = this.generateKeyDerivation(txPubKeyHex);
        return result ? this._bytesToHex(result) : null;
    }
    
    /**
     * Batch key derivation for scanning multiple transactions at once
     * Much more efficient than individual calls due to reduced JS/WASM overhead
     * 
     * @param {Array<Uint8Array|string>} txPubKeys - Array of 32-byte transaction public keys
     * @returns {Array<Uint8Array|null>} - Array of derivations (null for invalid points)
     */
    batchGenerateKeyDerivations(txPubKeys) {
        if (!this._initialized) throw new Error('Scanner not initialized');
        if (txPubKeys.length === 0) return [];
        
        const count = txPubKeys.length;
        
        // Resize batch buffers if needed
        if (count > this._batchSize) {
            if (this._batchDerivationsPtr) this.module._free(this._batchDerivationsPtr);
            if (this._batchTxPubsPtr) this.module._free(this._batchTxPubsPtr);
            
            this._batchDerivationsPtr = this.module._malloc(count * 32);
            this._batchTxPubsPtr = this.module._malloc(count * 32);
            this._batchSize = count;
            
            if (!this._batchDerivationsPtr || !this._batchTxPubsPtr) {
                throw new Error('Failed to allocate batch memory');
            }
        }
        
        // Copy all tx_pub keys to WASM memory
        for (let i = 0; i < count; i++) {
            const bytes = typeof txPubKeys[i] === 'string' 
                ? this._hexToBytes(txPubKeys[i]) 
                : txPubKeys[i];
                
            if (bytes.length !== 32) {
                throw new Error(`TX public key ${i} must be 32 bytes, got ${bytes.length}`);
            }
            
            this.module.HEAPU8.set(bytes, this._batchTxPubsPtr + (i * 32));
        }
        
        // Call batch derivation
        const successCount = this._fastBatchKeyDerivations(
            this._batchDerivationsPtr,
            this._batchTxPubsPtr,
            this._viewSecPtr,
            count
        );
        
        // Extract results
        const results = [];
        for (let i = 0; i < count; i++) {
            const derivation = new Uint8Array(
                this.module.HEAPU8.buffer, 
                this._batchDerivationsPtr + (i * 32), 
                32
            ).slice();
            
            // Check if derivation is all zeros (indicates invalid point)
            const isZero = derivation.every(b => b === 0);
            results.push(isZero ? null : derivation);
        }
        
        return results;
    }
    
    /**
     * Run benchmark to measure performance
     * @param {number} iterations - Number of key derivations to perform
     * @returns {object} - {iterations, successCount, avgMicroseconds}
     */
    benchmark(iterations = 1000) {
        if (!this._initialized) throw new Error('Scanner not initialized');
        
        const start = performance.now();
        const successCount = this._donna64Benchmark(iterations);
        const elapsed = performance.now() - start;
        
        return {
            iterations,
            successCount,
            totalMs: elapsed,
            avgMicroseconds: (elapsed * 1000) / iterations,
            derivationsPerSecond: Math.round((iterations / elapsed) * 1000)
        };
    }
    
    /**
     * Compare donna64 performance against reference implementation
     * @param {function} refGenerateKeyDerivation - Reference implementation to compare against
     * @param {number} iterations - Number of iterations
     */
    async compareBenchmark(refGenerateKeyDerivation, iterations = 100) {
        // Generate test data
        const testPub = new Uint8Array(32);
        const testSec = new Uint8Array(32);
        crypto.getRandomValues(testPub);
        crypto.getRandomValues(testSec);
        
        // Make valid points (just use reasonable test values)
        testSec[0] &= 0xF8; // Clear bottom 3 bits
        testSec[31] &= 0x7F; // Clear top bit
        testSec[31] |= 0x40; // Set bit 6
        
        this.setViewSecretKey(testSec);
        
        // Benchmark donna64
        const donna64Start = performance.now();
        for (let i = 0; i < iterations; i++) {
            this.generateKeyDerivation(testPub);
        }
        const donna64Time = performance.now() - donna64Start;
        
        // Benchmark reference
        const refStart = performance.now();
        for (let i = 0; i < iterations; i++) {
            await refGenerateKeyDerivation(testPub, testSec);
        }
        const refTime = performance.now() - refStart;
        
        return {
            donna64: {
                totalMs: donna64Time,
                avgMs: donna64Time / iterations
            },
            reference: {
                totalMs: refTime,
                avgMs: refTime / iterations
            },
            speedup: refTime / donna64Time
        };
    }
    
    // Helper: hex string to Uint8Array
    _hexToBytes(hex) {
        if (hex.length % 2 !== 0) {
            throw new Error('Invalid hex string length');
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }
    
    // Helper: Uint8Array to hex string
    _bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { Donna64Scanner };
} else if (typeof window !== 'undefined') {
    window.Donna64Scanner = Donna64Scanner;
}
