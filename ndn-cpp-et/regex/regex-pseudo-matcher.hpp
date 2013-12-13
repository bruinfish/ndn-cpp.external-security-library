/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_REGEX_PSEUDO_MATCHER_H
#define NDN_REGEX_PSEUDO_MATCHER_H

#include "regex-matcher.hpp"

namespace ndn
{
  class RegexPseudoMatcher : public RegexMatcher
  {
  public:
    RegexPseudoMatcher();

    ~RegexPseudoMatcher() 
    {}

    virtual void 
    compile() 
    {}

    void 
    setMatchResult(const std::string& str);

    void 
    resetMatchResult();
  };

}//ndn

#endif
