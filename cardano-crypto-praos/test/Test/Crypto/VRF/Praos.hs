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
    ]
