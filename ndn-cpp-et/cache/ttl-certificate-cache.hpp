/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_TTL_CERTIFICATE_CACHE_H
#define NDN_TTL_CERTIFICATE_CACHE_H

#include "certificate-cache.hpp"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/thread.hpp>

#include <unistd.h>
#include <map>

namespace ndn
{

  static ptr_lib::shared_ptr<Certificate> TCC_NULL_CERTIFICATE_PTR;
 
  class TTLCertificateCache : public CertificateCache
  {
  protected:
    typedef boost::posix_time::ptime Time;
    typedef std::list<Name> TrackerList;
    
    class TTLCacheEntry
    {
    public:
      TTLCacheEntry(const Time& timestamp, ptr_lib::shared_ptr<Certificate> certificate, TrackerList::iterator it)
        : m_timestamp(timestamp)
        , m_certificate(certificate)
        , m_it(it)
      {}

      Time m_timestamp;
      ptr_lib::shared_ptr<Certificate> m_certificate;
      TrackerList::iterator m_it;
    };
    
    typedef boost::recursive_mutex RecLock;
    typedef boost::unique_lock<RecLock> UniqueRecLock;
    typedef std::map<std::string, TTLCacheEntry> Cache;

  public:
    TTLCertificateCache(int maxSize = 1000, int interval = 60);
    
    virtual
    ~TTLCertificateCache();

    void
    start();
    
    void
    shutdown();
    
    virtual void
    insertCertificate(ptr_lib::shared_ptr<Certificate> certificate);

    virtual ptr_lib::shared_ptr<const Certificate> 
    getCertificate(const Name & certificateName, bool hasVersion=false);

    void
    printContent();
    
  private:
    void
    cleanLoop();
    
  protected:

    int m_maxSize;
    Cache m_cache;
    TrackerList m_lruList;
    RecLock m_mutex;
    boost::thread m_thread;
    bool m_running;
    int m_interval;
  };

}//ndn

#endif
