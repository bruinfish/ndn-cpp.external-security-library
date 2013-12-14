/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

#include "ndn-cpp-et/regex/regex-backref-manager.hpp"
#include "ndn-cpp-et/regex/regex-component-matcher.hpp"
#include "ndn-cpp-et/regex/regex-component-set-matcher.hpp"
#include "ndn-cpp-et/regex/regex-pattern-list-matcher.hpp"
#include "ndn-cpp-et/regex/regex-repeat-matcher.hpp"
#include "ndn-cpp-et/regex/regex-backref-matcher.hpp"
#include "ndn-cpp-et/regex/regex-top-matcher.hpp"
#include "ndn-cpp-et/regex/regex.hpp"

#define BOOST_TEST_MODULE RegexTests
#include <boost/test/unit_test.hpp>

#include <iostream>

using namespace ndn;
using namespace std;

BOOST_AUTO_TEST_SUITE(RegexTests)

BOOST_AUTO_TEST_CASE(ComponentMatcher)
{

  ptr_lib::shared_ptr<RegexBackrefManager> backRef = ptr_lib::make_shared<RegexBackrefManager>();
  ptr_lib::shared_ptr<RegexComponentMatcher> cm = ptr_lib::make_shared<RegexComponentMatcher>("a", backRef);
  bool res = cm->match(Name("/a/b/"), 0, 1);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));

  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexComponentMatcher>("a", backRef);
  res = cm->match(Name("/a/b/"), 1, 1);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexComponentMatcher>("(c+)\\.(cd)", backRef);
  res = cm->match(Name("/ccc.cd/b/"), 0, 1);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("ccc.cd"));
  BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[0].toEscapedString(), string("ccc"));
  BOOST_CHECK_EQUAL(backRef->getBackRef (1)->getMatchResult ()[0].toEscapedString(), string("cd"));
}

BOOST_AUTO_TEST_CASE (ComponentSetMatcher)
{

  ptr_lib::shared_ptr<RegexBackrefManager> backRef = ptr_lib::make_shared<RegexBackrefManager>();
  ptr_lib::shared_ptr<RegexComponentSetMatcher> cm = ptr_lib::make_shared<RegexComponentSetMatcher>("<a>", backRef);
  bool res = cm->match(Name("/a/b/"), 0, 1);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
    
  res = cm->match(Name("/a/b/"), 1, 1);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);
    
  res = cm->match(Name("/a/b/"), 0, 2);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexComponentSetMatcher>("[<a><b><c>]", backRef);
  res = cm->match(Name("/a/b/d"), 1, 1);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("b"));

  res = cm->match(Name("/a/b/d"), 2, 1);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);
 
  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexComponentSetMatcher>("[^<a><b><c>]", backRef);
  res = cm->match(Name("/b/d"), 1, 1);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);    
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("d"));

}

BOOST_AUTO_TEST_CASE (RepeatMatcher)
{

  ptr_lib::shared_ptr<RegexBackrefManager> backRef = ptr_lib::make_shared<RegexBackrefManager>();
  ptr_lib::shared_ptr<RegexRepeatMatcher> cm = ptr_lib::make_shared<RegexRepeatMatcher>("[<a><b>]*", backRef, 8);
  bool res = cm->match(Name("/a/b/c"), 0, 0);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  cm->match(Name("/a/b/c"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));



  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexRepeatMatcher>("[<a><b>]+", backRef, 8);
  res = cm->match(Name("/a/b/c"), 0, 0);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  res = cm->match(Name("/a/b/c"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));



  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexRepeatMatcher>("<.*>*", backRef, 4);
  res = cm->match(Name("/a/b/c/d/e/f/"), 0, 6);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toEscapedString(), string("d"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[4].toEscapedString(), string("e"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[5].toEscapedString(), string("f"));



  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexRepeatMatcher>("<>*", backRef, 2);
  res = cm->match(Name("/a/b/c/d/e/f/"), 0, 6);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toEscapedString(), string("d"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[4].toEscapedString(), string("e"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[5].toEscapedString(), string("f"));



  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexRepeatMatcher>("<a>?", backRef, 3);
  res = cm->match(Name("/a/b/c"), 0, 0);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  cm = ptr_lib::make_shared<RegexRepeatMatcher>("<a>?", backRef, 3);
  res = cm->match(Name("/a/b/c"), 0, 1);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));

  cm = ptr_lib::make_shared<RegexRepeatMatcher>("<a>?", backRef, 3);
  res = cm->match(Name("/a/b/c"), 0, 2);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);



  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexRepeatMatcher>("[<a><b>]{3}", backRef, 8);
  res = cm->match(Name("/a/b/a/d/"), 0, 2);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  res = cm->match(Name("/a/b/a/d/"), 0, 3);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 3);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("a"));

  res = cm->match(Name("/a/b/a/d/"), 0, 4);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);



  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexRepeatMatcher>("[<a><b>]{2,3}", backRef, 8);
  res = cm->match(Name("/a/b/a/d/e/"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));

  res = cm->match(Name("/a/b/a/d/e/"), 0, 3);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 3);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("a"));

  res = cm->match(Name("/a/b/a/b/e/"), 0, 4);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  res = cm->match(Name("/a/b/a/d/e/"), 0, 1);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);


  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexRepeatMatcher>("[<a><b>]{2,}", backRef, 8);
  res = cm->match(Name("/a/b/a/d/e/"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));

  res = cm->match(Name("/a/b/a/b/e/"), 0, 4);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toEscapedString(), string("b"));

  res = cm->match(Name("/a/b/a/d/e/"), 0, 1);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);


    
  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexRepeatMatcher>("[<a><b>]{,2}", backRef, 8);
  res = cm->match(Name("/a/b/a/b/e/"), 0, 3);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  res = cm->match(Name("/a/b/a/b/e/"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));

  res = cm->match(Name("/a/b/a/d/e/"), 0, 1);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));

  res = cm->match(Name("/a/b/a/d/e/"), 0, 0);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);
}

BOOST_AUTO_TEST_CASE (BackRefMatcher)
{

  ptr_lib::shared_ptr<RegexBackrefManager> backRef = ptr_lib::make_shared<RegexBackrefManager>();
  ptr_lib::shared_ptr<RegexBackrefMatcher> cm = ptr_lib::make_shared<RegexBackrefMatcher>("(<a><b>)", backRef);
  backRef->pushRef(boost::static_pointer_cast<RegexMatcher>(cm));
  cm->lateCompile();
  bool res = cm->match(Name("/a/b/c"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(backRef->size(), 1);

  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexBackrefMatcher>("(<a>(<b>))", backRef);
  backRef->pushRef(cm);
  cm->lateCompile();
  res = cm->match(Name("/a/b/c"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(backRef->size(), 2);
  BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(backRef->getBackRef (1)->getMatchResult ()[0].toEscapedString(), string("b"));
}

BOOST_AUTO_TEST_CASE (BackRefMatcherAdvanced)
{

  ptr_lib::shared_ptr<RegexBackrefManager> backRef = ptr_lib::make_shared<RegexBackrefManager>();
  ptr_lib::shared_ptr<RegexRepeatMatcher> cm = ptr_lib::make_shared<RegexRepeatMatcher>("([<a><b>])+", backRef, 10);
  bool res = cm->match(Name("/a/b/c"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(backRef->size(), 1);
  BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[0].toEscapedString(), string("b"));
}

BOOST_AUTO_TEST_CASE (BackRefMatcherAdvanced2)
{

  ptr_lib::shared_ptr<RegexBackrefManager> backRef = ptr_lib::make_shared<RegexBackrefManager>();
  ptr_lib::shared_ptr<RegexPatternListMatcher> cm = ptr_lib::make_shared<RegexPatternListMatcher>("(<a>(<b>))<c>", backRef);
  bool res = cm->match(Name("/a/b/c"), 0, 3);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 3);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));
  BOOST_CHECK_EQUAL(backRef->size(), 2);
  BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(backRef->getBackRef (0)->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(backRef->getBackRef (1)->getMatchResult ()[0].toEscapedString(), string("b"));
}

BOOST_AUTO_TEST_CASE (PatternListMatcher)
{

  ptr_lib::shared_ptr<RegexBackrefManager> backRef = ptr_lib::make_shared<RegexBackrefManager>();
  ptr_lib::shared_ptr<RegexPatternListMatcher> cm = ptr_lib::make_shared<RegexPatternListMatcher>("<a>[<a><b>]", backRef);
  bool res = cm->match(Name("/a/b/c"), 0, 2);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 2);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));

  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexPatternListMatcher>("<>*<a>", backRef);
  res = cm->match(Name("/a/b/c"), 0, 1);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 1);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));

  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexPatternListMatcher>("<>*<a>", backRef);
  res = cm->match(Name("/a/b/c"), 0, 2);
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  backRef = ptr_lib::make_shared<RegexBackrefManager>();
  cm = ptr_lib::make_shared<RegexPatternListMatcher>("<>*<a><>*", backRef);
  res = cm->match(Name("/a/b/c"), 0, 3);
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 3);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));

}

BOOST_AUTO_TEST_CASE (TopMatcher)
{

  ptr_lib::shared_ptr<RegexTopMatcher> cm = ptr_lib::make_shared<RegexTopMatcher>("^<a><b><c>");
  bool res = cm->match(Name("/a/b/c/d"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toEscapedString(), string("d"));

  cm = ptr_lib::make_shared<RegexTopMatcher>("<b><c><d>$");
  res = cm->match(Name("/a/b/c/d"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toEscapedString(), string("d"));

  cm = ptr_lib::make_shared<RegexTopMatcher>("^<a><b><c><d>$");
  res = cm->match(Name("/a/b/c/d"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toEscapedString(), string("d"));

  res = cm->match(Name("/a/b/c/d/e"));
  BOOST_CHECK_EQUAL(res, false);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 0);

  cm = ptr_lib::make_shared<RegexTopMatcher>("<a><b><c><d>");
  res = cm->match(Name("/a/b/c/d"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toEscapedString(), string("d"));


  cm = ptr_lib::make_shared<RegexTopMatcher>("<b><c>");
  res = cm->match(Name("/a/b/c/d"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[0].toEscapedString(), string("a"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[1].toEscapedString(), string("b"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[2].toEscapedString(), string("c"));
  BOOST_CHECK_EQUAL(cm->getMatchResult ()[3].toEscapedString(), string("d"));
}

BOOST_AUTO_TEST_CASE (TopMatcherAdvanced)
{
  ptr_lib::shared_ptr<Regex> cm = ptr_lib::make_shared<Regex>("^(<.*>*)<.*>");
  bool res = cm->match(Name("/n/a/b/c"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->expand("\\1"), Name("/n/a/b/"));

  cm = ptr_lib::make_shared<Regex>("^(<.*>*)<.*><c>(<.*>)<.*>");
  res = cm->match(Name("/n/a/b/c/d/e/"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
  BOOST_CHECK_EQUAL(cm->expand("\\1\\2"), Name("/n/a/d/"));

  cm = ptr_lib::make_shared<Regex>("(<.*>*)<.*>$");
  res = cm->match(Name("/n/a/b/c/"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->expand("\\1"), Name("/n/a/b/"));

  cm = ptr_lib::make_shared<Regex>("<.*>(<.*>*)<.*>$");
  res = cm->match(Name("/n/a/b/c/"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->expand("\\1"), Name("/a/b/"));

  cm = ptr_lib::make_shared<Regex>("<a>(<>*)<>$");
  res = cm->match(Name("/n/a/b/c/"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 4);
  BOOST_CHECK_EQUAL(cm->expand("\\1"), Name("/b/"));

  cm = ptr_lib::make_shared<Regex>("^<ndn><(.*)\\.(.*)><DNS>(<>*)<>");
  res = cm->match(Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
  BOOST_CHECK_EQUAL(cm->expand("<ndn>\\2\\1\\3"), Name("/ndn/edu/ucla/yingdi/mac/"));

  cm = ptr_lib::make_shared<Regex>("^<ndn><(.*)\\.(.*)><DNS>(<>*)<>", "<ndn>\\2\\1\\3");
  res = cm->match(Name("/ndn/ucla.edu/DNS/yingdi/mac/ksk-1/"));
  BOOST_CHECK_EQUAL(res, true);
  BOOST_CHECK_EQUAL(cm->getMatchResult ().size(), 6);
  BOOST_CHECK_EQUAL(cm->expand(), Name("/ndn/edu/ucla/yingdi/mac/"));
}

BOOST_AUTO_TEST_SUITE_END()
