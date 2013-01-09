/*
 * DiffieHellman.cpp
 *
 *  Created on: Nov 19, 2012
 *      Author: franziskus
 */

#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
#include <botan/sha2_32.h>
using namespace Botan;

#include <iostream>
#include <memory>

int main()
   {
   try
      {
      LibraryInitializer init;

      AutoSeeded_RNG rng;

      // Alice and Bob agree on a DH domain to use
      DL_Group shared_domain("modp/ietf/2048");

      // generate SPAKE public variables (M,N)
      BigInt tmp = BigInt(rng, (size_t)1024);
      BigInt M = power_mod(shared_domain.get_g(), tmp, shared_domain.get_p());
      tmp = BigInt(rng, (size_t)1024);
      BigInt N = power_mod(shared_domain.get_g(), tmp, shared_domain.get_p());
//      std::cout << "M: " << M << "\n" << "N: " << N << "\n";

      // Alice creates a DH key
      DH_PrivateKey private_a(rng, shared_domain);
//      std::cout << "x: " << private_a.get_x() << "\n";
//      std::cout << "public_value: " << private_a.public_value() << "\n";
//      std::cout << "public_value(BigInt): " << BigInt::decode(private_a.public_value()) << "\n";
//      std::cout << "y: " << private_a.get_y() << "\n";
//      std::cout << "p: " << private_a.get_domain().get_p() << " length: " << private_a.get_domain().get_p().bits() << "\n";
//      BigInt y2 = power_mod(private_a.get_domain().get_g(), private_a.get_x(), private_a.get_domain().get_p());
//      std::cout << "y2: " << y2 << "\n";

      // Bob creates a key with a matching group
      DH_PrivateKey private_b(rng, shared_domain);

//      MemoryVector<byte> public_a = private_a.public_value();
//      MemoryVector<byte> public_b = private_b.public_value();
      // Alice sends to Bob her public key and a session parameter
      // include password here
      std::string pwd = "Password";
      const byte* pwdB = (byte*)&pwd[0];
      BigInt pwdNum = BigInt::decode(pwdB, pwd.length(), BigInt::Binary);
      BigInt public_aBigInt = private_a.get_y()*(power_mod(M, pwdNum, shared_domain.get_p()));
      MemoryVector<byte> public_a;
      public_a = BigInt::encode(public_aBigInt);

      const std::string session_param = "Alice and Bob's shared session parameter";

      // Bob sends his public key to Alice
      // include password here
      BigInt public_bBigInt = private_b.get_y()*(power_mod(N, pwdNum, shared_domain.get_p()));
      MemoryVector<byte> public_b;
      public_b = BigInt::encode(public_bBigInt);

      // compute k for alice
      BigInt NPW = power_mod(N, pwdNum, shared_domain.get_p());
      BigInt KA = power_mod(public_bBigInt*(inverse_mod(NPW, shared_domain.get_p())), private_a.get_x(), shared_domain.get_p());
//      BigInt KA2 = power_mod(public_bBigInt, private_a.get_x(), shared_domain.get_p());
      std::cout << "K_A: " << KA << "\n";
      // compute k for bob
      BigInt MPW = power_mod(M, pwdNum, shared_domain.get_p());
      BigInt KB = power_mod(public_aBigInt*(inverse_mod(MPW, shared_domain.get_p())), private_b.get_x(), shared_domain.get_p());
//      BigInt KB2 = power_mod(public_aBigInt, private_b.get_x(), shared_domain.get_p());
      std::cout << "K_B: " << KB << "\n";


      // Now Alice performs the key agreement operation
//      PK_Key_Agreement ka_alice(private_a, "KDF2(SHA-256)");
//      SymmetricKey alice_key = ka_alice.derive_key(32, public_b, session_param);

      SHA_256 h;
      h.update(session_param);
      h.update(BigInt::encode(public_aBigInt));
      h.update(BigInt::encode(public_bBigInt));
      h.update(BigInt::encode(pwdNum));
      h.update(BigInt::encode(KA));
      OctetString alice_key = OctetString(h.final());

      // Bob does the same:
//      PK_Key_Agreement ka_bob(private_b, "KDF2(SHA-256)");
//      SymmetricKey bob_key = ka_bob.derive_key(32, public_a, session_param);
      h.update(session_param);
      h.update(BigInt::encode(public_aBigInt));
      h.update(BigInt::encode(public_bBigInt));
      h.update(BigInt::encode(pwdNum));
      h.update(BigInt::encode(KB));
      OctetString bob_key = OctetString(h.final());

      if(alice_key == bob_key)
         {
         std::cout << "The two keys matched, everything worked\n";
         std::cout << "The shared key was: " << alice_key.as_string() << "\n"; //.as_string()
         }
      else
         {
         std::cout << "The two keys didn't match! Hmmm...\n";
         std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
         std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
         }

      // Now use the shared key for encryption or MACing or whatever
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
