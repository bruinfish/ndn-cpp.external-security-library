/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_SEC_POLICY_SIMPLE_HPP
#define NDN_SEC_POLICY_SIMPLE_HPP

#include <ndn-cpp-dev/security/sec-policy.hpp>
#include <ndn-cpp-dev/security/identity-certificate.hpp>

#include <map>
#include "sec-rule-relative.hpp"
#include "../regex/regex.hpp"
#include "../cache/certificate-cache.hpp"


namespace ndn {

class SecPolicySimple : public SecPolicy
{
public:
  struct Error : public SecPolicy::Error { Error(const std::string &what) : SecPolicy::Error(what) {} };
  
  typedef std::vector< ptr_lib::shared_ptr<SecRuleRelative> > RuleList;
  typedef std::vector< ptr_lib::shared_ptr<Regex> > RegexList;
  
  static const ptr_lib::shared_ptr<CertificateCache> DEFAULT_CERTIFICATE_CACHE_PTR;
  
public:
  SecPolicySimple(const int stepLimit = 10,
                  ptr_lib::shared_ptr<CertificateCache> certificateCache = DEFAULT_CERTIFICATE_CACHE_PTR);
  
  virtual 
  ~SecPolicySimple() {}
  
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
  addSigningPolicyRule (ptr_lib::shared_ptr<SecRuleRelative> rule);
  
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
  addVerificationPolicyRule (ptr_lib::shared_ptr<SecRuleRelative> rule);
  
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
  std::map<Name, ptr_lib::shared_ptr<IdentityCertificate> > m_trustAnchors;
};

void 
SecPolicySimple::addSigningPolicyRule (ptr_lib::shared_ptr<SecRuleRelative> rule)
{ rule->isPositive() ? m_signPolicies.push_back(rule) : m_mustFailSign.push_back(rule); }

void
SecPolicySimple::addSigningInference (ptr_lib::shared_ptr<Regex> inference)
{ m_signInference.push_back(inference); }

void 
SecPolicySimple::addVerificationPolicyRule (ptr_lib::shared_ptr<SecRuleRelative> rule)
{ rule->isPositive() ? m_verifyPolicies.push_back(rule) : m_mustFailVerify.push_back(rule); }
      
void 
SecPolicySimple::addVerificationExemption (ptr_lib::shared_ptr<Regex> exempt)
{ m_verifyExempt.push_back(exempt); }

void  
SecPolicySimple::addTrustAnchor(ptr_lib::shared_ptr<IdentityCertificate> certificate)
{ m_trustAnchors[certificate->getName().getPrefix(-1)] = certificate; }

}//ndn

#endif
