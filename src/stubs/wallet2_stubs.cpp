
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>

#include <cstring>
#include <stdarg.h>
#include <stdio.h>

const char *i18n_translate(const char *s, const std::string &context) {

  return s;
}

extern "C" {
const char *i18n_get_language() { return "en"; }

int i18n_set_language(const char *directory, const char *language,
                      std::string &error) {

  return 0;
}
}

namespace i18n {
const char *tr(const char *s) { return s; }
}

#include "hardforks/hardforks.h"

const hardfork_t mainnet_hard_forks[] = {

    {1, 1, 0, 1341378000},

    {2, 89800, 0, 1729518000},

    {3, 121100, 0, 1734516900},

    {4, 121800, 0, 1734607000},

    {5, 136100, 0, 1736265945},

    {6, 154750, 0, 1738336000},

    {7, 161900, 0, 1739264400},

    {8, 172000, 0, 1740390000},

    {9, 179200, 0, 1740393800},

    {10, 334750, 0, 1759142500},
};
const size_t num_mainnet_hard_forks =
    sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]);
const uint64_t mainnet_hard_fork_version_1_till = ((uint64_t)-1);

const hardfork_t testnet_hard_forks[] = {
    {1, 1, 0, 1341378000},
    {2, 250, 0, 1445355000},
    {3, 500, 0, 1729518000},
    {4, 600, 0, 1734607000},
};
const size_t num_testnet_hard_forks =
    sizeof(testnet_hard_forks) / sizeof(testnet_hard_forks[0]);
const uint64_t testnet_hard_fork_version_1_till = ((uint64_t)-1);

const hardfork_t stagenet_hard_forks[] = {
    {1, 1, 0, 1341378000},
};
const size_t num_stagenet_hard_forks =
    sizeof(stagenet_hard_forks) / sizeof(stagenet_hard_forks[0]);
