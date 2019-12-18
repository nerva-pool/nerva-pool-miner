#include <curl/curl.h> 
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <list>
#include <set>
#include <string>
#include <boost/thread/thread.hpp>

#include "xnv_https.h"
#include "cryptonote_config.h"
#include "version.h"
#include "misc_log_ex.h"
#include "common/dns_utils.h"

namespace xnvhttp
{
    std::string get_host(std::string ip)
    {
        size_t found = ip.find_first_of(":");
        std::string host = ip.substr(0, found);
        return host;
    }

    std::vector<std::string> resolve_dns_addresses(std::vector<std::string> node_list)
    {
      std::vector<std::string> full_addrs = {};
      std::vector<std::vector<std::string>> dns_results;
      dns_results.resize(node_list.size());

      boost::thread::attributes thread_attributes;
      thread_attributes.set_stack_size(1024*1024);

      std::list<boost::thread> dns_threads;
      uint64_t result_index = 0;
      for (const std::string& addr_str : node_list)
      {
        boost::thread th = boost::thread(thread_attributes, [=, &dns_results, &addr_str]
        {
          MDEBUG("dns_threads[" << result_index << "] created for: " << addr_str);
          // TODO: care about dnssec avail/valid
          bool avail, valid;
          std::vector<std::string> addr_list;

          try
          {
            addr_list = tools::DNSResolver::instance().get_ipv4(addr_str, avail, valid);
            MDEBUG("dns_threads[" << result_index << "] DNS resolve done");
            boost::this_thread::interruption_point();
          }
          catch(const boost::thread_interrupted&)
          {
            // thread interruption request
            // even if we now have results, finish thread without setting
            // result variables, which are now out of scope in main thread
            MWARNING("dns_threads[" << result_index << "] interrupted");
            return;
          }

          MINFO("dns_threads[" << result_index << "] addr_str: " << addr_str << "  number of results: " << addr_list.size());
          dns_results[result_index] = addr_list;
        });

        dns_threads.push_back(std::move(th));
        ++result_index;
      }

      MDEBUG("dns_threads created, now waiting for completion or timeout of " << CRYPTONOTE_DNS_TIMEOUT_MS << "ms");
      boost::chrono::system_clock::time_point deadline = boost::chrono::system_clock::now() + boost::chrono::milliseconds(CRYPTONOTE_DNS_TIMEOUT_MS);
      uint64_t i = 0;
      for (boost::thread& th : dns_threads)
      {
        if (! th.try_join_until(deadline))
        {
          MWARNING("dns_threads[" << i << "] timed out, sending interrupt");
          th.interrupt();
        }
        ++i;
      }

      i = 0;
      for (const auto& result : dns_results)
      {
        MDEBUG("DNS lookup for " << node_list[i] << ": " << result.size() << " results");
        // if no results for node, thread's lookup likely timed out
        if (result.size())
        {
          for (const auto& addr_string : result)
            full_addrs.push_back(addr_string);
        }
        ++i;
      }

      return full_addrs;
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

        std::vector<std::string> url_list = xnvhttp::resolve_dns_addresses(::config::testnet::dns_seed_nodes);

        for (const std::string &a : url_list)
        {
            std::string url = "http://" + xnvhttp::get_host(a) + "/xnv_blacklist.txt";

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
        std::vector<std::string> url_list = testnet ? ::config::testnet::dns_seed_nodes : ::config::dns_seed_nodes;

        for (const std::string &a : url_list)
        {
            std::string url = "http://" + xnvhttp::get_host(a) + "/api/analytics/submit/";
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
                    MGINFO("Curl returned error: " << curl_easy_strerror(res));
            } 
        }
        
        MGINFO("Sending analytics failed");
        return false;
    }
}
