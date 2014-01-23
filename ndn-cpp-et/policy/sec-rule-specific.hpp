/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef SEC_RULE_SPECIFIC_H
#define SEC_RULE_SPECIFIC_H

#include "sec-rule.hpp"
#include "../regex/regex.hpp"

class SecRuleSpecific : public ndn::SecRule
{
  
public:
  SecRuleSpecific(ndn::ptr_lib::shared_ptr<ndn::Regex> dataRegex,
                  ndn::ptr_lib::shared_ptr<ndn::Regex> signerRegex);

  SecRuleSpecific(const SecRuleSpecific& rule);

  virtual
  ~SecRuleSpecific() {};

  bool 
  matchDataName(const ndn::Data& data);

  bool 
  matchSignerName(const ndn::Data& data);

  bool
  satisfy(const ndn::Data& data);

  bool
  satisfy(const ndn::Name& dataName, const ndn::Name& signerName);
  
private:
  ndn::ptr_lib::shared_ptr<ndn::Regex> m_dataRegex;
  ndn::ptr_lib::shared_ptr<ndn::Regex> m_signerRegex;
};

#endif
