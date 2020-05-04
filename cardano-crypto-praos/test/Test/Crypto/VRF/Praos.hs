{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
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
import Test.Tasty.HUnit (testCase, assertEqual)
-- import Test.Tasty.QuickCheck (testProperty)
import Foreign.C.Types

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
        assertEqual "" (fromIntegral crypto_vrf_seedbytes) (length $ rawSeed seed)
    ]
