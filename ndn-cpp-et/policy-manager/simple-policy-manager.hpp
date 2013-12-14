/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_SIMPLE_POLICY_MANAGER_H
#define NDN_SIMPLE_POLICY_MANAGER_H

#include <ndn-cpp/security/policy/policy-manager.hpp>

#include <map>
#include "identity-policy-rule.hpp"
#include "ndn-cpp-et/regex/regex.hpp"
#include "ndn-cpp-et/cache/certificate-cache.hpp"
#include <ndn-cpp/security/certificate/identity-certificate.hpp>


namespace ndn {

  static ptr_lib::shared_ptr<CertificateCache> SPM_NULL_CERTIFICATE_CACHE_PTR;
  static ptr_lib::shared_ptr<ValidationRequest> SPM_NULL_VALIDATION_REQUEST_PTR;
  static ptr_lib::shared_ptr<IdentityCertificate> SPM_NULL_IDENTITY_CERTIFICATE_PTR;

  class SimplePolicyManager : public PolicyManager
  {
  public:
    typedef std::vector< ptr_lib::shared_ptr<IdentityPolicyRule> > RuleList;
    typedef std::vector< ptr_lib::shared_ptr<Regex> > RegexList;

  public:
    SimplePolicyManager(const int stepLimit = 10,
                        ptr_lib::shared_ptr<CertificateCache> certificateCache = SPM_NULL_CERTIFICATE_CACHE_PTR);

    virtual 
    ~SimplePolicyManager() {}

    /**
     * @brief check if the received data packet can escape from verification
     * @param data the received data packet
     * @return true if the data does not need to be verified, otherwise false
     */
    virtual bool 
    skipVerifyAndTrust (const Data& data);

    /**
     * @brief check if PolicyManager has the verification rule for the received data
     * @param data the received data packet
     * @return true if the data must be verified, otherwise false
     */
    virtual bool
    requireVerify (const Data& data);

    /**
     * @brief check whether received data packet complies with the verification policy, and get the indication of next verification step
     * @param data the received data packet
     * @param stepCount the number of verification steps that have been done, used to track the verification progress
     * @param verifiedCallback the callback function that will be called if the received data packet has been validated
     * @param unverifiedCallback the callback function that will be called if the received data packet cannot be validated
     * @return the indication of next verification step, NULL if there is no further step
     */
    virtual ptr_lib::shared_ptr<ValidationRequest>
    checkVerificationPolicy(const ptr_lib::shared_ptr<Data>& data, 
			    int stepCount, 
			    const OnVerified& onVerified, 
			    const OnVerifyFailed& onVerifyFailed);

    
    /**
     * @brief check if the signing certificate name and data name satify the signing policy 
     * @param dataName the name of data to be signed
     * @param certificateName the name of signing certificate
     * @return true if the signing certificate can be used to sign the data, otherwise false
     */
    virtual bool 
    checkSigningPolicy(const Name& dataName, const Name& certificateName);
    
    /**
     * @brief Infer signing identity name according to policy, if the signing identity cannot be inferred, it should return empty name
     * @param dataName, the name of data to be signed
     * @return the signing identity. 
     */
    virtual Name 
    inferSigningIdentity(const Name& dataName);

    /**
     * @brief add a rule to check whether a signing certificate is allowed to sign a data 
     * @param policy the signing policy
     */
    inline virtual void 
    addSigningPolicyRule (ptr_lib::shared_ptr<IdentityPolicyRule> policy);

    /**
     * @brief add a rule to infer the signing identity for a data packet
     * @param inference the signing inference
     */
    inline virtual void 
    addSigningInference(ptr_lib::shared_ptr<Regex> inference);

    /**
     * @brief add a rule to check whether the data name and signing certificate name comply with the policy
     * @param policy the verification policy
     */
    inline virtual void
    addVerificationPolicyRule (ptr_lib::shared_ptr<IdentityPolicyRule> policy);

    /**
     * @brief add a rule to exempt a data packet from verification 
     * @param exempt the exemption rule
     */
    inline virtual void
    addVerificationExemption(ptr_lib::shared_ptr<Regex> exempt);

    /**
     * @brief add a trust anchor
     * @param certificate the trust anchor 
     */
    inline virtual void 
    addTrustAnchor(ptr_lib::shared_ptr<IdentityCertificate> certificate);

  protected:
    virtual void
    onCertificateVerified(ptr_lib::shared_ptr<Data> certificate, 
                          ptr_lib::shared_ptr<Data> data, 
                          const OnVerified& onVerified, 
                          const OnVerifyFailed& onVerifyFailed);

    virtual void
    onCertificateUnverified(ptr_lib::shared_ptr<Data>signCertificate, 
                            ptr_lib::shared_ptr<Data>data, 
                            const OnVerifyFailed& onVerifyFailed);
    
  protected:
    int m_stepLimit;
    ptr_lib::shared_ptr<CertificateCache> m_certificateCache;
    RuleList m_mustFailVerify;
    RuleList m_verifyPolicies;
    RegexList m_verifyExempt;
    RuleList m_signPolicies;
    RuleList m_mustFailSign;
    RegexList m_signInference;
    std::map<std::string, ptr_lib::shared_ptr<IdentityCertificate> > m_trustAnchors;
  };

  inline void 
  SimplePolicyManager::addSigningPolicyRule (ptr_lib::shared_ptr<IdentityPolicyRule> policy)
  { policy->isPositive() ? m_signPolicies.push_back(policy) : m_mustFailSign.push_back(policy); }

  inline void
  SimplePolicyManager::addSigningInference (ptr_lib::shared_ptr<Regex> inference)
  { m_signInference.push_back(inference); }

  inline void 
  SimplePolicyManager::addVerificationPolicyRule (ptr_lib::shared_ptr<IdentityPolicyRule> policy)
  { policy->isPositive() ? m_verifyPolicies.push_back(policy) : m_mustFailVerify.push_back(policy); }
      
  inline void 
  SimplePolicyManager::addVerificationExemption (ptr_lib::shared_ptr<Regex> exempt)
  { m_verifyExempt.push_back(exempt); }

  inline void  
  SimplePolicyManager::addTrustAnchor(ptr_lib::shared_ptr<IdentityCertificate> certificate)
  {
    Name certName = certificate->getName();
    m_trustAnchors.insert(std::pair<std::string, ptr_lib::shared_ptr<IdentityCertificate> >(certName.getPrefix(certName.size()-1).toUri(), certificate)); 
  }

}//ndn

#endif
