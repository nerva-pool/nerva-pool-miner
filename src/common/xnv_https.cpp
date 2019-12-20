#include <curl/curl.h> 
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
    std::string m_read_buffer;

    const std::vector<std::string> get_ip_list() { return ip_list; }

    size_t curl_write_callback(void *ptr, size_t size, size_t count, void *stream)
    { 
        size_t sz = size * count;
        ((std::string*)stream)->append((char*)ptr, 0, sz);
        return sz;
    }

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

    void read_blacklist_from_url(const bool testnet)
    {
        if (!testnet)
            return;

        if (!dns_config::has_seed_node_records())
            return;

        std::vector<std::string> url_list = dns_config::get_seed_node_records();

        for (const std::string &a : url_list)
        {
            std::string url = "http://" + a + "/xnv_blacklist.txt";

            CURL* curl = curl_easy_init(); 
            if(curl) 
            {
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); 
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m_read_buffer);
                curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
                CURLcode res = curl_easy_perform(curl); 
                curl_easy_cleanup(curl); 
                if (res != CURLE_OK)
                    continue;
                break;
            } 
        }

        ip_list = split_string(m_read_buffer, "\n");
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

        for (const std::string &a : url_list)
        {
            std::string url = "http://" + a + "/api/analytics/submit/";
            MGINFO("Sending analytics to " << url);

            std::string user_agent = "nerva-cli/";
            user_agent.append(MONERO_VERSION);

            CURL* curl = curl_easy_init(); 
            if(curl) 
            {
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); 
                curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
                curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());
                CURLcode res = curl_easy_perform(curl); 
                curl_easy_cleanup(curl); 
                if (res == CURLE_OK)
                {
                    MGINFO("Sending analytics successful");
                    return true;
                }
                else
                    MGINFO("Curl returned error code: " << res << " (" << curl_easy_strerror(res) << ")");
            } 
        }
        
        MGINFO("Sending analytics failed");
        return false;
    }
}
