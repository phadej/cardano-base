{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}
module Test.Crypto.VRF.Praos
  ( tests
  )
where

import Cardano.Crypto.VRF.Praos

-- import Cardano.Binary (FromCBOR, ToCBOR (..))
-- import Cardano.Crypto.VRF
-- import Data.Proxy (Proxy (..))
-- import Test.Crypto.Orphans.Arbitrary ()
-- import Test.Crypto.Util (Seed, prop_cbor, withSeed)
-- import Test.QuickCheck ((==>), Property, counterexample)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (testCase, assertEqual, assertBool)
-- import Test.Tasty.QuickCheck (testProperty)
import Foreign.C.Types
import qualified Data.ByteString as BS

--
-- The list of all tests
--
tests :: TestTree
tests =
  testGroup "Crypto.VRF.Praos"
    [ testCase "crypto_vrf_proofbytes" $ do
        let actual = crypto_vrf_proofbytes
            expected = 80 :: CSize
        assertEqual "" expected actual
    , testCase "crypto_vrf_publickeybytes" $ do
        let actual = crypto_vrf_publickeybytes
            expected = 32 :: CSize
        assertEqual "" expected actual
    , testCase "crypto_vrf_secretkeybytes" $ do
        let actual = crypto_vrf_secretkeybytes
            expected = 64 :: CSize
        assertEqual "" expected actual
    , testCase "crypto_vrf_seedbytes" $ do
        let actual = crypto_vrf_seedbytes
            expected = 32 :: CSize
        assertEqual "" expected actual
    , testCase "crypto_vrf_outputbytes" $ do
        let actual = crypto_vrf_outputbytes
            expected = 64 :: CSize
        assertEqual "" expected actual

    , testCase "genSeed" $ do
        seed <- genSeed
        let expected = fromIntegral crypto_vrf_seedbytes :: Int
        actual <- BS.length <$> unsafeRawSeed seed
        assertEqual "" expected actual

    , testCase "VRF round-trip" $ do
        seed <- genSeed
        let (pk, sk) = keypairFromSeed seed
        let msg = "Hello, world!" :: BS.ByteString
            mproof = prove sk msg
        case mproof of
          Nothing ->
            assertBool "Proof failure" False
          Just proof -> do
            let moutput = verify pk proof msg
            case moutput of
              Nothing ->
                assertBool "Verification failure" False
              Just output -> do
                hash <- outputToByteString output
                print hash
                assertEqual "Hash length" 64 (BS.length hash)
                pure ()
    ]
