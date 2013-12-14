/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include "identity-policy-rule.hpp"

#include <ndn-cpp/sha256-with-rsa-signature.hpp>
#include <ndn-cpp/security/security-common.hpp>
#include <ndn-cpp/security/security-exception.hpp>



#include "logging.h"

INIT_LOGGER ("IdentityPolicyRule");

using namespace std;

namespace ndn
{

  IdentityPolicyRule::IdentityPolicyRule (const string& dataRegex, const string& signerRegex, const string& op, 
					  const string& dataExpand, const string& signerExpand, bool isPositive)
    : PolicyRule(PolicyRule::IDENTITY_POLICY, isPositive),
      m_dataRegex(dataRegex),
      m_signerRegex(signerRegex),
      m_op(op),
      m_dataExpand(dataExpand),
      m_signerExpand(signerExpand),
      m_dataNameRegex(dataRegex, dataExpand),
      m_signerNameRegex(signerRegex, signerExpand)
  {
    if(op != ">" && op != ">=" && op != "==")
      throw SecurityException("op is wrong!");
  }

  IdentityPolicyRule::~IdentityPolicyRule()
  { }

  bool 
  IdentityPolicyRule::satisfy (const Data& data)
  {
    Name dataName = data.getName();
    
    DigestAlgorithm digestAlg = DIGEST_ALGORITHM_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType && DIGEST_ALGORITHM_SHA256 == digestAlg)
      {
	const Sha256WithRsaSignature* sigPtr = dynamic_cast<const Sha256WithRsaSignature*> (data.getSignature());
	Name signerName = sigPtr->getKeyLocator().getKeyName();
        
        return satisfy (dataName, signerName);
      }
       
    return false;
  }
  
  bool 
  IdentityPolicyRule::satisfy (const Name& dataName, const Name& signerName)
  {
    // _LOG_DEBUG("Rule: " << *toXmlElement());
    // _LOG_DEBUG("dataName: "  << dataName << " signerName: " << signerName);

    if(!m_dataNameRegex.match(dataName))
       return false;
    Name expandDataName = m_dataNameRegex.expand();

    if(!m_signerNameRegex.match(signerName))
      return false;
    Name expandSignerName =  m_signerNameRegex.expand();

    bool matched = compare(expandDataName, expandSignerName);
    
    // _LOG_DEBUG("DataName: " << expandDataName << " SignerName: " << expandSignerName << " Matched: " << matched);

    return matched;
  }

  bool 
  IdentityPolicyRule::matchDataName (const Data& data)
  {
    return m_dataNameRegex.match(data.getName());
  }

  bool
  IdentityPolicyRule::matchSignerName (const Data& data)
  {    
    DigestAlgorithm digestAlg = DIGEST_ALGORITHM_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType && DIGEST_ALGORITHM_SHA256 == digestAlg)
      {
        const Sha256WithRsaSignature* sigPtr = dynamic_cast<const Sha256WithRsaSignature*> (data.getSignature());
        Name signerName = sigPtr->getKeyLocator().getKeyName();
        return m_signerNameRegex.match(signerName);
      }
    
    return false;
  }

  bool 
  IdentityPolicyRule::compare(const Name & dataName, const Name & signerName)
  {
    // _LOG_DEBUG("data namespace: " << dataName.toUri());
    // _LOG_DEBUG("signer namespace: " << signerName.toUri());


    
    if((dataName == signerName) && ("==" == m_op || ">=" == m_op))
      return true;
    
    
    Name::const_iterator i = dataName.begin ();
    Name::const_iterator j = signerName.begin ();

    for (; i != dataName.end () && j != signerName.end (); i++, j++)
      {
	string iString = i->toEscapedString();
	string jString = j->toEscapedString();
	int res = iString.compare(jString);

	if (res == 0)
	  continue;
	else
	  return false;
    }
    
    if(i == dataName.end())
      return false;
    else
      return true;
  }

}//ndn
