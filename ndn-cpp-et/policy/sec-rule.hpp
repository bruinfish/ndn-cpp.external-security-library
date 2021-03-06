/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_SEC_RULE_HPP
#define NDN_SEC_RULE_HPP

#include <ndn-cpp-dev/data.hpp>

namespace ndn
{

class SecRule
{
public:
  struct Error : public std::runtime_error { Error(const std::string &what) : std::runtime_error(what) {} };
  
  SecRule(bool isPositive)
  : m_isPositive(isPositive)
  {}
  
  virtual 
  ~SecRule() 
  {}
  
  virtual bool 
  matchDataName(const Data& data) = 0;
  
  virtual bool 
  matchSignerName(const Data& data) = 0;
  
  virtual bool
  satisfy(const Data& data) = 0;
  
  virtual bool
  satisfy(const Name& dataName, const Name& signerName) = 0;
  
  inline bool
  isPositive();
  
protected:
  bool m_isPositive;
};

bool
SecRule::isPositive()
{
  return m_isPositive;
}
    
}

#endif
