/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include "sec-rule-identity.hpp"

#include <ndn-cpp-dev/security/signature-sha256-with-rsa.hpp>
#include <ndn-cpp-dev/security/security-common.hpp>



#include "logging.h"

INIT_LOGGER ("SecRuleIdentity");

using namespace std;

namespace ndn
{

  SecRuleIdentity::SecRuleIdentity (const string& dataRegex, const string& signerRegex, const string& op, 
                                    const string& dataExpand, const string& signerExpand, bool isPositive)
    : SecRule(isPositive),
      m_dataRegex(dataRegex),
      m_signerRegex(signerRegex),
      m_op(op),
      m_dataExpand(dataExpand),
      m_signerExpand(signerExpand),
      m_dataNameRegex(dataRegex, dataExpand),
      m_signerNameRegex(signerRegex, signerExpand)
  {
    if(op != ">" && op != ">=" && op != "==")
      throw Error("op is wrong!");
  }

  SecRuleIdentity::~SecRuleIdentity()
  { }

  bool 
  SecRuleIdentity::satisfy (const Data& data)
  {
    Name dataName = data.getName();
    
    DigestAlgorithm digestAlg = DIGEST_ALGORITHM_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType && DIGEST_ALGORITHM_SHA256 == digestAlg)
      {
	SignatureSha256WithRsa sig(data.getSignature());
	const Name &signerName = sig.getKeyLocator().getName();
        
        return satisfy (dataName, signerName);
      }
       
    return false;
  }
  
  bool 
  SecRuleIdentity::satisfy (const Name& dataName, const Name& signerName)
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
  SecRuleIdentity::matchDataName (const Data& data)
  {
    return m_dataNameRegex.match(data.getName());
  }

  bool
  SecRuleIdentity::matchSignerName (const Data& data)
  {    
    DigestAlgorithm digestAlg = DIGEST_ALGORITHM_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType && DIGEST_ALGORITHM_SHA256 == digestAlg)
      {
        SignatureSha256WithRsa sig(data.getSignature());
        const Name &signerName = sig.getKeyLocator().getName();
        return m_signerNameRegex.match(signerName);
      }
    
    return false;
  }

  bool 
  SecRuleIdentity::compare(const Name & dataName, const Name & signerName)
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
