/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#ifndef NDN_REGEX_EXCEPTION_H
#define NDN_REGEX_EXCEPTION_H

#include <exception>
#include <string>

namespace ndn
{
  class RegexException : public std::exception {
  public:
    RegexException(const std::string & errMsg) throw()
      : m_errMsg(errMsg)
    {}
    
    ~RegexException() throw()
    {}
    
    const char* what() const throw()
    { return m_errMsg.c_str(); }
    
  private:
    const std::string m_errMsg;
  };

}//ndn

#endif
