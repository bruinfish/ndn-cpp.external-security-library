/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */


#ifndef NDN_IDENTITY_POLICY_RULE_H
#define NDN_IDENTITY_POLICY_RULE_H

#include "policy-rule.hpp"
#include "ndn-cpp-et/regex/regex.hpp"

namespace ndn
{
  
  class IdentityPolicyRule : public PolicyRule
  {
  public:
    IdentityPolicyRule(const std::string& dataRegex, const std::string& signerRegex, const std::string& op, 
		       const std::string& dataExpand, const std::string& signerExpand, bool isPositive);

    virtual
    ~IdentityPolicyRule();
    
    virtual bool 
    matchDataName(const Data& data);

    virtual bool 
    matchSignerName(const Data& data);

    virtual bool
    satisfy(const Data& data);

    virtual bool
    satisfy(const Name& dataName, const Name& signerName);

  private:
    bool 
    compare(const Name& dataName, const Name& signerName);

  private:
    const std::string m_dataRegex;
    const std::string m_signerRegex;
    const std::string m_op;
    const std::string m_dataExpand;
    const std::string m_signerExpand;

    Regex m_dataNameRegex;
    Regex m_signerNameRegex;
  };

}//ndn

#endif
