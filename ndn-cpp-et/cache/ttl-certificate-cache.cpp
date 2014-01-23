/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include "ttl-certificate-cache.hpp"

#include <iostream>

#include "logging.h"


INIT_LOGGER("TTLCertificateCache")

using namespace std;
using namespace boost;

namespace ndn
{    


class TTLCertificateCache::TTLCacheEntry
{
public:
  TTLCacheEntry()
  {}

  TTLCacheEntry(const Time& timestamp, ptr_lib::shared_ptr<Certificate> certificate, TrackerList::iterator it)
    : m_timestamp(timestamp)
    , m_certificate(certificate)
    , m_it(it)
  {}

  Time m_timestamp;
  ptr_lib::shared_ptr<Certificate> m_certificate;
  TrackerList::iterator m_it;
};
   

TTLCertificateCache::TTLCertificateCache(int maxSize, int interval)
  : m_maxSize(maxSize)
  , m_running(true)
  , m_interval(interval)
{ start(); }

TTLCertificateCache::~TTLCertificateCache()
{ shutdown(); }

void
TTLCertificateCache::start()
{
  // TODO: When we merge it to ndn-cpp-dev, we will get rid of this thread and use io_service to schedule necessary cleaning up event.
  m_thread = thread (&TTLCertificateCache::cleanLoop, this); 
}

void
TTLCertificateCache::shutdown()
{
  
  {
    UniqueRecLock lock(m_mutex);
    m_running = false;
  }    
  m_thread.interrupt();
  m_thread.join ();
  
}
  
void
TTLCertificateCache::insertCertificate(ptr_lib::shared_ptr<Certificate> certificate)
{
  Name name = certificate->getName().getPrefix(-1);
  Time expire = posix_time::microsec_clock::universal_time() + posix_time::milliseconds(certificate->getFreshnessPeriod());
  
  {
    UniqueRecLock lock(m_mutex);
    Cache::iterator it = m_cache.find(name);
    if(it != m_cache.end())
      {
        m_lruList.splice(m_lruList.end(), m_lruList, it->second.m_it);
        it->second.m_timestamp = expire;
        it->second.m_certificate = certificate;
      }
    else
      {
        while(m_lruList.size() >= m_maxSize)
          {
            m_cache.erase(m_lruList.front());
            m_lruList.pop_front();
          }
        TrackerList::iterator it = m_lruList.insert(m_lruList.end(), name);
        m_cache[name] = TTLCacheEntry(expire, certificate, it);
      }
  }
}

ptr_lib::shared_ptr<const Certificate> 
TTLCertificateCache::getCertificate(const Name & certificateName)
{
  {
    UniqueRecLock lock(m_mutex);
    Cache::iterator it = m_cache.find(certificateName);
    if(it != m_cache.end())
      {
        m_lruList.splice(m_lruList.end(), m_lruList, it->second.m_it);
        return it->second.m_certificate;
      }
    else
      return ptr_lib::shared_ptr<const Certificate>();
  }
}

void
TTLCertificateCache::cleanLoop()
{
  while(m_running)
    {
      Time now = boost::posix_time::microsec_clock::universal_time();
      {
        UniqueRecLock lock(m_mutex);
        // _LOG_DEBUG("Round: " << boost::posix_time::to_iso_string(now));
        Cache::iterator it = m_cache.begin();
        for(;it != m_cache.end(); it++)
          {
            // _LOG_DEBUG("size: " << m_cache.size() << " " << it->second.m_it->toUri() << " timestamp: " << boost::posix_time::to_iso_string(it->second.m_timestamp));
            if(now > it->second.m_timestamp)
              {
                // _LOG_DEBUG("ERASE");
                m_lruList.erase(it->second.m_it);
                m_cache.erase(it);
              }
          }
      }        
      try{
#if BOOST_VERSION >= 1050000
        this_thread::sleep_for(chrono::seconds(m_interval));
#else
        this_thread::sleep(posix_time::seconds(m_interval));
#endif
      }catch(thread_interrupted& e){
        break;
      }
    }
}

void
TTLCertificateCache::printContent()
{
  TrackerList::iterator it = m_lruList.begin();
  for(; it != m_lruList.end(); it++)
        cout << it->toUri() << " ";
  cout << endl;
}

}//ndn


