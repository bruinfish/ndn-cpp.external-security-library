/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_CERTIFICATE_CACHE_H
#define NDN_CERTIFICATE_CACHE_H

#include <ndn-cpp/name.hpp>
#include <ndn-cpp/security/certificate/certificate.hpp>

namespace ndn
{

  class CertificateCache
  {
  public:
    virtual
    ~CertificateCache() {}
    
    virtual void
    insertCertificate(ptr_lib::shared_ptr<Certificate> certificate) = 0;

    virtual ptr_lib::shared_ptr<const Certificate> 
    getCertificate(const Name& certificateName, bool hasVersion=false) = 0;
  };

}//ndn

#endif
