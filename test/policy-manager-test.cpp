/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Yingdi Yu <yingdi@cs.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

// #define BOOST_TEST_MODULE PolicyManagerTests
#include <boost/test/unit_test.hpp>

#include <ndn-cpp/face.hpp>
#include <ndn-cpp/security/identity/basic-identity-storage.hpp>
#include <ndn-cpp/security/identity/osx-private-key-storage.hpp>
#include <ndn-cpp/security/identity/identity-manager.hpp>
#include <ndn-cpp/security/key-chain.hpp>

#include "ndn-cpp-et/policy-manager/simple-policy-manager.hpp"

#include <iostream>

#include <cryptopp/base64.h>

using namespace ndn;
using namespace std;

BOOST_AUTO_TEST_SUITE(PolicyManagerTests)

void
onVerified(const ptr_lib::shared_ptr<Data>& data)
{
  string content((const char*)data->getContent().buf(), data->getContent().size());
  cout << "Verified Content: " << content << endl;
}

void
onVerifyFailed(const ptr_lib::shared_ptr<Data>& data)
{
  string content((const char*)data->getContent().buf(), data->getContent().size());
  cout << "Cannot Verify Content: " << content << endl;
}

void 
onData(const ptr_lib::shared_ptr<const Interest>& interest, 
       const ptr_lib::shared_ptr<Data>& data,
       ptr_lib::shared_ptr<KeyChain> keyChain)
{
  keyChain->verifyData(data, bind(&onVerified, _1), bind(&onVerifyFailed, _1));
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
           const ptr_lib::shared_ptr<const Data>& data)
{
  cout << "on Interest!" << endl;
  Blob encodedData = data->wireEncode();
  cout << encodedData.size() << endl;
  transport.send(*encodedData);
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
  data->wireDecode((const uint8_t*)decoded.c_str(), decoded.size());

  return ptr_lib::make_shared<IdentityCertificate>(*data);
  // return ptr_lib::make_shared<IdentityCertificate>();
}

BOOST_AUTO_TEST_CASE(SimplePolicyManagerTest)
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
    // Connect to port 6363 until the testbed hubs use NDNx.
    Face face("localhost", 6363);
    
    ptr_lib::shared_ptr<BasicIdentityStorage> publicStorage = ptr_lib::make_shared<BasicIdentityStorage>();
    ptr_lib::shared_ptr<OSXPrivateKeyStorage> privateStorage = ptr_lib::make_shared<OSXPrivateKeyStorage>();
    ptr_lib::shared_ptr<IdentityManager> identityManager = ptr_lib::make_shared<IdentityManager>(publicStorage, privateStorage);
    ptr_lib::shared_ptr<SimplePolicyManager> policyManager = ptr_lib::make_shared<SimplePolicyManager>();
    
    ptr_lib::shared_ptr<IdentityPolicyRule> rule1 = ptr_lib::make_shared<IdentityPolicyRule>("^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>",
                                                                                             "^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>$",
                                                                                             ">", "\\1\\2", "\\1", true);
    ptr_lib::shared_ptr<IdentityPolicyRule> rule2 = ptr_lib::make_shared<IdentityPolicyRule>("^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>",
                                                                                             "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$",
                                                                                             "==", "\\1", "\\1\\2", true);
    ptr_lib::shared_ptr<IdentityPolicyRule> rule3 = ptr_lib::make_shared<IdentityPolicyRule>("^(<>*)$", 
                                                                                             "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$", 
                                                                                             ">", "\\1", "\\1\\2", true);

    policyManager->addVerificationPolicyRule(rule1);
    policyManager->addVerificationPolicyRule(rule2);
    policyManager->addVerificationPolicyRule(rule3);

    policyManager->addTrustAnchor(root);

    ptr_lib::shared_ptr<KeyChain> keyChain = ptr_lib::make_shared<KeyChain>(identityManager, policyManager);

    keyChain->setFace(&face);


    Name name1("/ndn/edu/ucla/cs/yingdi/tmp03");
    Name certificateName = identityManager->getDefaultCertificateName();

    cout << certificateName.toUri() << endl;

    ptr_lib::shared_ptr<Data> data = ptr_lib::make_shared<Data>(name1);
    string content("abcd");
    data->setContent((const uint8_t *)&content[0], content.size());
    data->getMetaInfo().setTimestampMilliseconds(time(NULL) * 1000.0);
    keyChain->sign(*data, certificateName);

    face.registerPrefix(name1, boost::bind(onInterest, _1, _2, _3, _4, data), boost::bind(onRegisterFailed, _1));
  
    
    Name name2("/ndn/edu/ucla/cs/yingdi/tmp03");    
    cout << "Express name " << name2.toUri() << endl;
    // Use bind to pass the counter object to the callbacks.
    face.expressInterest(name2, boost::bind(onData, _1, _2, keyChain), boost::bind(onTimeout, _1));
    
    // The main event loop.
    while (true) {
      face.processEvents();
      // We need to sleep for a few milliseconds so we don't use 100% of the CPU.
      usleep(10000);
    }
  } catch (std::exception& e) {
    cout << "exception: " << e.what() << endl;
  }
}

BOOST_AUTO_TEST_SUITE_END()



