/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include "sec-policy-simple.hpp"

#include <ndn-cpp/security/verifier.hpp>
#include <ndn-cpp/security/signature-sha256-with-rsa.hpp>
#include "../cache/ttl-certificate-cache.hpp"

#include <boost/bind.hpp>
#include <cryptopp/rsa.h>

#include "logging.h"

#if NDN_CPP_HAVE_CXX11
// In the std library, the placeholders are in a different namespace than boost.
using namespace ndn::func_lib::placeholders;
#endif

INIT_LOGGER("SecPolicySimple");

using namespace std;

namespace ndn
{

  SecPolicySimple::SecPolicySimple(const int stepLimit,
					   ptr_lib::shared_ptr<CertificateCache> certificateCache)
    : m_stepLimit(stepLimit)
    , m_certificateCache(certificateCache)
  {
    if(m_certificateCache == SPM_NULL_CERTIFICATE_CACHE_PTR)
      m_certificateCache = ptr_lib::make_shared<TTLCertificateCache>();
  }

  bool
  SecPolicySimple::requireVerify (const Data& data)
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
  SecPolicySimple::skipVerifyAndTrust (const Data& data)
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
  SecPolicySimple::onCertificateVerified(ptr_lib::shared_ptr<Data>signCertificate, 
					     ptr_lib::shared_ptr<Data>data, 
					     const OnVerified& onVerified, 
					     const OnVerifyFailed& onVerifyFailed)
  {
    ptr_lib::shared_ptr<IdentityCertificate> certificate = ptr_lib::make_shared<IdentityCertificate>(*signCertificate);

    if(!certificate->isTooLate() && !certificate->isTooEarly())
      {
        m_certificateCache->insertCertificate(certificate);

        try{
          if(Verifier::verifySignature(*data, data->getSignature(), certificate->getPublicKeyInfo()))
            {
              onVerified(data);
              return;
            }
        }catch(Signature::Error &e){
          _LOG_DEBUG("SecPolicySimple Error: " << e.what());
          onVerifyFailed(data);
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
  SecPolicySimple::onCertificateUnverified(ptr_lib::shared_ptr<Data>signCertificate, 
					       ptr_lib::shared_ptr<Data>data, 
					       const OnVerifyFailed& onVerifyFailed)
  { onVerifyFailed(data); }

  ptr_lib::shared_ptr<ValidationRequest>
  SecPolicySimple::checkVerificationPolicy(const ptr_lib::shared_ptr<Data>& data, 
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
            try{
              SignatureSha256WithRsa sig(data->getSignature());                
              
              Name keyLocatorName = sig.getKeyLocator().getName();
              ptr_lib::shared_ptr<const Certificate> trustedCert;
              if(m_trustAnchors.end() == m_trustAnchors.find(keyLocatorName.toUri()))
                trustedCert = m_certificateCache->getCertificate(keyLocatorName);
              else
                trustedCert = m_trustAnchors[keyLocatorName.toUri()];

              if(static_cast<bool>(trustedCert)){
                if(Verifier::verifySignature(*data, sig, trustedCert->getPublicKeyInfo()))
                  onVerified(data);
                else
                  onVerifyFailed(data);
                onVerifyFailed(data);

                return SPM_NULL_VALIDATION_REQUEST_PTR;
              }
              else{
                // _LOG_DEBUG("KeyLocator is not trust anchor");                
                OnVerified recursiveVerifiedCallback = func_lib::bind(&SecPolicySimple::onCertificateVerified, 
                                                                      this, 
                                                                      _1, 
                                                                      data, 
                                                                      onVerified, 
                                                                      onVerifyFailed);

                OnVerifyFailed recursiveUnverifiedCallback = func_lib::bind(&SecPolicySimple::onCertificateUnverified, 
                                                                            this, 
                                                                            _1, 
                                                                            data, 
                                                                            onVerifyFailed);


                ptr_lib::shared_ptr<Interest> interest = ptr_lib::make_shared<Interest>(boost::cref(sig.getKeyLocator().getName()));

                ptr_lib::shared_ptr<ValidationRequest> nextStep = ptr_lib::make_shared<ValidationRequest>(interest, 
                                                                                                          recursiveVerifiedCallback,
                                                                                                          recursiveUnverifiedCallback,
                                                                                                          3,
                                                                                                          stepCount + 1);
                return nextStep;
              }
            }catch(SignatureSha256WithRsa::Error &e){
              _LOG_DEBUG("SecPolicySimple Error: " << e.what());
              onVerifyFailed(data);
              return SPM_NULL_VALIDATION_REQUEST_PTR; 
            }catch(KeyLocator::Error &e){
              _LOG_DEBUG("SecPolicySimple Error: " << e.what());
              onVerifyFailed(data);
              return SPM_NULL_VALIDATION_REQUEST_PTR; 
            }
          }
      }
    
    onVerifyFailed(data);
    return SPM_NULL_VALIDATION_REQUEST_PTR;
  }

  bool 
  SecPolicySimple::checkSigningPolicy(const Name & dataName, const Name & certName)
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
  SecPolicySimple::inferSigningIdentity(const Name & dataName)
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
