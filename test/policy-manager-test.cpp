/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

// #define BOOST_TEST_MODULE PolicyManagerTests
#include <boost/test/unit_test.hpp>

#include <ndn-cpp-dev/face.hpp>
#include <ndn-cpp-dev/security/key-chain.hpp>
#include <ndn-cpp-dev/security/verifier.hpp>

#include "ndn-cpp-et/policy/sec-policy-simple.hpp"

#include <iostream>

#include <cryptopp/base64.h>

using namespace ndn;
using namespace std;

BOOST_AUTO_TEST_SUITE(PolicyTests)

void
onVerified(const ptr_lib::shared_ptr<Data>& data)
{
  string content((const char*)data->getContent().value(), data->getContent().value_size());
  cout << "Verified Content: " << content << endl;
}

void
onVerifyFailed(const ptr_lib::shared_ptr<Data>& data)
{
  string content(reinterpret_cast<const char*>(data->getContent().value()), data->getContent().value_size());
  cout << "Cannot Verify Content: " << content << endl;
}

void 
onData(const ptr_lib::shared_ptr<const Interest>& interest, 
       const ptr_lib::shared_ptr<Data>& data,
       ptr_lib::shared_ptr<Verifier> verifier)
{
  verifier->verifyData(data, bind(&onVerified, _1), bind(&onVerifyFailed, _1));
}

void 
onTimeout(const ptr_lib::shared_ptr<const Interest>& interest)
{
  cout << "Time out!" << endl;
}

void
onInterest(const ptr_lib::shared_ptr<const Name>& prefix, 
           const ptr_lib::shared_ptr<const Interest>& interest, 
           Transport& transport, 
           uint64_t registeredPrefixId,
           const ptr_lib::shared_ptr<const Data>& data,
           const ptr_lib::shared_ptr<Face>& face)
{
  cout << "on Interest!" << endl;
  face->put(*data);
}

void
onRegisterFailed(const ptr_lib::shared_ptr<const Name>& prefix)
{
  cout << "on Register Failed" << endl;
}

ptr_lib::shared_ptr<IdentityCertificate> 
getRoot(const string & TrustAnchor)
{
  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(TrustAnchor.c_str()), 
                             TrustAnchor.size(), 
                             true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  ptr_lib::shared_ptr<Data> data = ptr_lib::make_shared<Data>();
  data->wireDecode(Block(decoded.c_str(), decoded.size()));

  return ptr_lib::make_shared<IdentityCertificate>(*data);
  // return ptr_lib::make_shared<IdentityCertificate>();
}

BOOST_AUTO_TEST_CASE(SecPolicySimpleTest)
{

  //ndn ksk
const string TrustAnchor("BIICqgOyEIWlKzDI2xX2hdq5Azheu9IVyewcV4uM7ylfh67Y8MIxF3tDCTx5JgEn\
HYMuCaYQm6XuaXTlVfDdWff/K7Xebq8IgGxjNBeU9eMf7Gy9iIMrRAOdBG0dBHmo\
67biGs8F+P1oh1FwKu/FN1AE9vh8HSOJ94PWmjO+6PvITFIXuI3QbcCz8rhvbsfb\
5X/DmfbJ8n8c4X3nVxrBm6fd4z8kOFOvvhgJImvqsow69Uy+38m8gJrmrcWMoPBJ\
WsNLcEriZCt/Dlg7EqqVrIn6ukylKCvVrxA9vm/cEB74J/N+T0JyMRDnTLm17gpq\
Gd75rhj+bLmpOMOBT7Nb27wUKq8gcXzeAADy+p1uZG4A+p1LRVkA+vVrc2stMTM4\
MzMyNTcyMAD6vUlELUNFUlQA+q39PgurHgAAAaID4gKF5vjua9EIr3/Fn8k1AdSc\
nEryjVDW3ikvYoSwjK7egTkAArq1BSc+C6sdAAHiAery+p1uZG4A+p1LRVkA+vVr\
c2stMTM4MzMyNTcyMAD6vUlELUNFUlQAAAAAAAGaFr0wggFjMCIYDzIwMTMxMTAx\
MTcxMTIyWhgPMjAxNDExMDExNzExMjJaMBkwFwYDVQQpExBORE4gVGVzdGJlZCBS\
b290MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA06x+elwzWCHa4I3b\
yrYCMAIVxQpRVLuOXp0h+BS+5GNgMVPi7+40o4zSJG+kiU8CIH1mtj8RQAzBX9hF\
I5VAyOC8nS8D8YOfBwt2yRDZPgt1E5PpyYUBiDYuq/zmJDL8xjxAlxrMzVOqD/uj\
/vkkcBM/T1t9Q6p1CpRyq+GMRbV4EAHvH7MFb6bDrH9t8DHEg7NPUCaSQBrd7PvL\
72P+QdiNH9zs/EiVzAkeMG4iniSXLuYM3z0gMqqcyUUUr6r1F9IBmDO+Kp97nZh8\
VCL+cnIEwyzAFAupQH5GoXUWGiee8oKWwH2vGHX7u6sWZsCp15NMSG3OC4jUIZOE\
iVUF1QIBEQAA");

  ptr_lib::shared_ptr<IdentityCertificate> root = getRoot(TrustAnchor);

  try {
    ptr_lib::shared_ptr<Face> face = ptr_lib::make_shared<Face>();

    ptr_lib::shared_ptr<KeyChain> keyChain = ptr_lib::make_shared<KeyChain>();
    ptr_lib::shared_ptr<SecPolicySimple> policy = ptr_lib::make_shared<SecPolicySimple>();
    ptr_lib::shared_ptr<Verifier> verifier = ptr_lib::make_shared<Verifier>(policy);
    verifier->setFace(face);
    
    ptr_lib::shared_ptr<SecRuleIdentity> rule1 = ptr_lib::make_shared<SecRuleIdentity>("^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>",
                                                                                       "^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>$",
                                                                                       ">", "\\1\\2", "\\1", true);
    ptr_lib::shared_ptr<SecRuleIdentity> rule2 = ptr_lib::make_shared<SecRuleIdentity>("^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>",
                                                                                       "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$",
                                                                                       "==", "\\1", "\\1\\2", true);
    ptr_lib::shared_ptr<SecRuleIdentity> rule3 = ptr_lib::make_shared<SecRuleIdentity>("^(<>*)$", 
                                                                                       "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$", 
                                                                                       ">", "\\1", "\\1\\2", true);

    policy->addVerificationPolicyRule(rule1);
    policy->addVerificationPolicyRule(rule2);
    policy->addVerificationPolicyRule(rule3);

    policy->addTrustAnchor(root);

    Name name0("/ndn/edu/ucla/cs/yingdi/tmp04");
    face->expressInterest(name0, boost::bind(onData, _1, _2, verifier), boost::bind(onTimeout, _1));


    Name name("/ndn/edu/ucla/cs/yingdi/tmp05");
    Name certificateName = keyChain->getDefaultCertificateName();

    cout << certificateName.toUri() << endl;

    ptr_lib::shared_ptr<Data> data = ptr_lib::make_shared<Data>(name);
    string content("abcd");
    data->setContent((const uint8_t *)&content[0], content.size());
    keyChain->sign(*data, certificateName);

    face->put(*data);
    face->setInterestFilter(name, boost::bind(onInterest, _1, _2, _3, _4, data, face), boost::bind(onRegisterFailed, _1));
  
    
    cout << "Express name " << name << endl;
    // Use bind to pass the counter object to the callbacks.
    face->expressInterest(name, boost::bind(onData, _1, _2, verifier), boost::bind(onTimeout, _1));
    
    face->processEvents();
  } catch (std::exception& e) {
    cout << "exception: " << e.what() << endl;
  }
}

BOOST_AUTO_TEST_SUITE_END()



