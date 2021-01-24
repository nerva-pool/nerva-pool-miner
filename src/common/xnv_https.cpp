#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>

#include "xnv_https.h"
#include "cryptonote_config.h"
#include "version.h"
#include "misc_log_ex.h"
#include "common/dns_utils.h"
#include "common/dns_config.h"
#include "net/http_client.h"

namespace xnvhttp
{
    std::string get_host(std::string ip)
    {
        size_t found = ip.find_first_of(":");
        std::string host = ip.substr(0, found);
        return host;
    }
}

namespace blacklist
{
    const std::vector<std::string> get_ip_list() { return ip_list; }

    std::vector<std::string> split_string(const std::string& str, const std::string& delimiter)
    {
        std::vector<std::string> strings;

        std::string::size_type pos = 0;
        std::string::size_type prev = 0;
        while ((pos = str.find(delimiter, prev)) != std::string::npos)
        {
            strings.push_back(str.substr(prev, pos - prev));
            prev = pos + 1;
        }

        return strings;
    }

    void read_blacklist_from_url()
    {
        if (!dns_config::has_seed_node_records())
            return;

        std::vector<std::string> url_list = dns_config::get_seed_node_records();

        epee::net_utils::http::http_simple_client http_client;
        const epee::net_utils::http::http_response_info *info = NULL;
        epee::net_utils::http::url_content u_c;

        for (const std::string &a : url_list)
        {
            std::string url = "http://" + a + "/api/admin/blacklist/";

            if (!epee::net_utils::parse_url(url, u_c))
                continue;

            http_client.set_server(a, boost::none);

            if (!http_client.connect(std::chrono::seconds(30)))
                continue;

            if (!http_client.invoke_get(u_c.uri, std::chrono::seconds(30), "", &info))
                continue;

            http_client.disconnect();

            if (!info)
                continue;
            
            if (info->m_response_code != 200)
            {
                MGINFO(url << " response code: " << info->m_response_code);
                MGINFO(info->m_body);
                continue;
            }

            ip_list = split_string(info->m_body, "\n");
        }
    }
}

namespace analytics
{
    void enable(bool enabled) { m_enabled = enabled; }
    bool is_enabled() { return m_enabled; }

    bool contact_server(const bool testnet)
    {
        if (testnet)
            return false;

        if (!dns_config::has_seed_node_records())
            return false;

        std::vector<std::string> url_list = dns_config::get_seed_node_records();

        std::string user_agent = "nerva-cli/" + std::string(MONERO_VERSION);

        epee::net_utils::http::http_simple_client http_client;
        const epee::net_utils::http::http_response_info *info = NULL;
        epee::net_utils::http::url_content u_c;
        epee::net_utils::http::fields_list fields;
        fields.push_back(std::make_pair(u8"User-Agent", user_agent));

        for (const std::string &a : url_list)
        {
            std::string url = "http://" + a + "/api/analytics/submit/";
            MGINFO("Sending analytics to " << url);

            if (!epee::net_utils::parse_url(url, u_c))
                continue;

            http_client.set_server(a, boost::none);

            if (!http_client.connect(std::chrono::seconds(30)))
                continue;

            if (!http_client.invoke_get(u_c.uri, std::chrono::seconds(30), "", &info, fields))
                continue;

            http_client.disconnect();

            if (!info)
                continue;
            
            if (info->m_response_code != 200)
            {
                MGINFO(url << " response code: " << info->m_response_code);
                MGINFO(info->m_body);
                continue;
            }

            return true;
        }
        
        MGINFO("Sending analytics failed");
        return false;
    }
}
