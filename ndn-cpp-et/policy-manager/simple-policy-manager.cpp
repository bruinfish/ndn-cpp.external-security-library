/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include "simple-policy-manager.hpp"

#include <ndn-cpp/security/security-exception.hpp>
#include <ndn-cpp/sha256-with-rsa-signature.hpp>
#include <ndn-cpp/security/signature/sha256-with-rsa-handler.hpp>
#include "ndn-cpp-et/cache/ttl-certificate-cache.hpp"

#include <boost/bind.hpp>
#include <cryptopp/rsa.h>

#include "logging.h"

INIT_LOGGER("SimplePolicyManager");

using namespace std;

namespace ndn
{

  SimplePolicyManager::SimplePolicyManager(const int stepLimit,
					   ptr_lib::shared_ptr<CertificateCache> certificateCache)
    : m_stepLimit(stepLimit)
    , m_certificateCache(certificateCache)
  {
    if(m_certificateCache == SPM_NULL_CERTIFICATE_CACHE_PTR)
      m_certificateCache = ptr_lib::make_shared<TTLCertificateCache>();
  }

  bool
  SimplePolicyManager::requireVerify (const Data& data)
  {
    RuleList::iterator it = m_verifyPolicies.begin();
    for(; it != m_verifyPolicies.end(); it++)
      {
	if((*it)->matchDataName(data))
	  return true;
      }

    it = m_mustFailVerify.begin();
    for(; it != m_mustFailVerify.end(); it++)
      {
	if((*it)->matchDataName(data))
	  return true;
      }

    return false;
  }

  bool 
  SimplePolicyManager::skipVerifyAndTrust (const Data& data)
  {
    RegexList::iterator it = m_verifyExempt.begin();
    for(; it != m_verifyExempt.end(); it++)
      {
	if((*it)->match(data.getName()))
	  return true;
      }

    return false;
  }

  void
  SimplePolicyManager::onCertificateVerified(ptr_lib::shared_ptr<Data>signCertificate, 
					     ptr_lib::shared_ptr<Data>data, 
					     const OnVerified& onVerified, 
					     const OnVerifyFailed& onVerifyFailed)
  {
    ptr_lib::shared_ptr<IdentityCertificate> certificate = ptr_lib::make_shared<IdentityCertificate>(*signCertificate);

    if(!certificate->isTooLate() && !certificate->isTooEarly())
      {
        m_certificateCache->insertCertificate(certificate);

        if(Sha256WithRsaHandler::verifySignature(*data, certificate->getPublicKeyInfo()))
          {
            onVerified(data);
            return;
          }
      }
    else
      {
        onVerifyFailed(data);
        return;
      }
  }

  void
  SimplePolicyManager::onCertificateUnverified(ptr_lib::shared_ptr<Data>signCertificate, 
					       ptr_lib::shared_ptr<Data>data, 
					       const OnVerifyFailed& onVerifyFailed)
  { onVerifyFailed(data); }

  ptr_lib::shared_ptr<ValidationRequest>
  SimplePolicyManager::checkVerificationPolicy(const ptr_lib::shared_ptr<Data>& data, 
					       int stepCount, 
					       const OnVerified& onVerified, 
					       const OnVerifyFailed& onVerifyFailed)
  {
    if(m_stepLimit == stepCount){
      _LOG_DEBUG("reach the maximum steps of verification");
      onVerifyFailed(data);
      return SPM_NULL_VALIDATION_REQUEST_PTR;
    }

    RuleList::iterator it = m_mustFailVerify.begin();
    for(; it != m_mustFailVerify.end(); it++)
      {
	if((*it)->satisfy(*data))
          {
            onVerifyFailed(data);
            return SPM_NULL_VALIDATION_REQUEST_PTR;
          }
      }

    it = m_verifyPolicies.begin();
    for(; it != m_verifyPolicies.end(); it++)
      {
	if((*it)->satisfy(*data))
          {
            const Sha256WithRsaSignature* sigPtr = dynamic_cast<const Sha256WithRsaSignature*> (data->getSignature());    

            if(ndn_KeyLocatorType_KEYNAME != sigPtr->getKeyLocator().getType())
              {
                onVerifyFailed(data);
		return SPM_NULL_VALIDATION_REQUEST_PTR;
              }

	    const Name& keyLocatorName = sigPtr->getKeyLocator().getKeyName();
	    ptr_lib::shared_ptr<const Certificate> trustedCert;
            if(m_trustAnchors.end() == m_trustAnchors.find(keyLocatorName.toUri()))
              trustedCert = m_certificateCache->getCertificate(keyLocatorName);
	    else
              trustedCert = m_trustAnchors[keyLocatorName.toUri()];

            if(SPM_NULL_IDENTITY_CERTIFICATE_PTR != trustedCert){
              if(Sha256WithRsaHandler::verifySignature(*data, trustedCert->getPublicKeyInfo()))
		onVerified(data);
              else
		onVerifyFailed(data);
	      return SPM_NULL_VALIDATION_REQUEST_PTR;
            }
            else{
              _LOG_DEBUG("KeyLocator is not trust anchor");

              OnVerified recursiveVerifiedCallback = boost::bind(&SimplePolicyManager::onCertificateVerified, 
								 this, 
								 _1, 
								 data, 
								 onVerified, 
								 onVerifyFailed);

              OnVerifyFailed recursiveUnverifiedCallback = boost::bind(&SimplePolicyManager::onCertificateUnverified, 
								       this, 
								       _1, 
								       data, 
								       onVerifyFailed);


	      ptr_lib::shared_ptr<Interest> interest = ptr_lib::make_shared<Interest>(sigPtr->getKeyLocator().getKeyName());
              interest->setChildSelector(ndn_Interest_CHILD_SELECTOR_RIGHT);

	      ptr_lib::shared_ptr<ValidationRequest> nextStep = ptr_lib::make_shared<ValidationRequest>(interest, 
													recursiveVerifiedCallback,
													recursiveUnverifiedCallback,
													3,
													stepCount + 1);
              return nextStep;
            }
          }
      }
    
    onVerifyFailed(data);
    return SPM_NULL_VALIDATION_REQUEST_PTR;
  }

  bool 
  SimplePolicyManager::checkSigningPolicy(const Name & dataName, const Name & certName)
  {
    RuleList::iterator it = m_mustFailSign.begin();
    for(; it != m_mustFailSign.end(); it++)
      {
	if((*it)->satisfy(dataName, certName))
	  return false;
      }

    it = m_signPolicies.begin();
    for(; it != m_signPolicies.end(); it++)
      {
	if((*it)->satisfy(dataName, certName))
	  return true;
      }

    return false;
  }
  
  Name
  SimplePolicyManager::inferSigningIdentity(const Name & dataName)
  {
    RegexList::iterator it = m_signInference.begin();
    for(; it != m_signInference.end(); it++)
      {
	if((*it)->match(dataName))
	  return (*it)->expand();
      }

    return Name();
  }

}//ndn
