// Copyright (c) 2017-2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include "misc_log_ex.h"
#include "log.hpp"

namespace hw {

  #undef MONERO_DEFAULT_LOG_CATEGORY
  #define MONERO_DEFAULT_LOG_CATEGORY "device"

  void buffer_to_str(char *to_buff,  size_t to_len, const char *buff, size_t len) {
    CHECK_AND_ASSERT_THROW_MES(to_len > (len*2), "destination buffer too short. At least" << (len*2+1) << " bytes required");
    for (size_t i=0; i<len; i++) {
      sprintf(to_buff+2*i, "%.02x", (unsigned char)buff[i]);
    }
  }

  void log_hexbuffer(const std::string &msg,  const char* buff, size_t len) {
    char logstr[1025];
    buffer_to_str(logstr, sizeof(logstr),  buff, len);
    MDEBUG(msg<< ": " << logstr);
  }

  void log_message(const std::string &msg, const std::string &info ) {
    MDEBUG(msg << ": " << info);
  }


  #ifdef WITH_DEVICE_LEDGER    
    namespace ledger {
    
    #undef MONERO_DEFAULT_LOG_CATEGORY
    #define MONERO_DEFAULT_LOG_CATEGORY "device.ledger"

  }
  #endif //WITH_DEVICE_LEDGER    

}
