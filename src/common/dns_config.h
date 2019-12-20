// Copyright (c) 2019, The NERVA Project

#ifndef _XNV_DNS_CONFIG_
#define _XNV_DNS_CONFIG_

#include <vector>
#include <string>
#include "cryptonote_config.h"

namespace dns_config
{
    static const std::vector<std::string> SEED_NODES = {
        "xnv1.getnerva.org",
        "xnv2.getnerva.org",
        "xnv3.getnerva.org",
        "xnv4.getnerva.org",
        "xnv5.getnerva.org",
        "xnv6.getnerva.org"
    };

    static const std::vector<std::string> CHECKPOINTS = {
        "checkpoint.getnerva.org"
    };

    static const std::vector<std::string> UPDATE = {
        "update.getnerva.org"
    };

    static const std::string ROOT_DOMAIN = "getnerva.org";

    namespace testnet
    {
        static const std::vector<std::string> SEED_NODES = {
            "xnv1-tn.getnerva.org",
            "xnv2-tn.getnerva.org",
        };

        static const std::vector<std::string> CHECKPOINTS = {
            "checkpoint-tn.getnerva.org"
        };
    }

    void init(const bool testnet);

    std::vector<std::string> get_update_records();
    std::vector<std::string> get_seed_node_records();
    bool has_update_records();
    bool has_seed_node_records();
    bool is_dnssec_ok();

    struct dns_config_t
    {
        std::vector<std::string> const SEED_NODES;
        std::vector<std::string> const CHECKPOINTS;
    };

    inline const dns_config_t &get_config(cryptonote::network_type nettype)
    {
        static const dns_config_t mainnet = {
            ::dns_config::SEED_NODES,
            ::dns_config::CHECKPOINTS
        };

        static const dns_config_t testnet = {
            ::dns_config::SEED_NODES,
            ::dns_config::CHECKPOINTS
        };

        static const dns_config_t empty = { {}, {} };

        switch (nettype)
        {
            case cryptonote::MAINNET:
                return mainnet;
            case cryptonote::TESTNET:
                return testnet;
            default:
                return empty;
        }
    }
}
#endif