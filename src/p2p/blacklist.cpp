#include <curl/curl.h> 
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <set>
#include <string>
#include "blacklist.h"
#include "cryptonote_config.h"

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

    std::string get_host(std::string ip)
    {
        size_t found = ip.find_first_of(":");
        std::string host = ip.substr(0, found);
        return host;
    }

    void read_blacklist_from_url(const bool testnet)
    {
        std::set<std::string> seed_node_aliases = testnet ? 
            ::config::testnet::seed_node_aliases : ::config::seed_node_aliases;

        for (const std::string &a : seed_node_aliases)
        {
            std::string url;
            url.append("https://");
            url.append(a);
            url.append("/xnv_blacklist.txt");

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