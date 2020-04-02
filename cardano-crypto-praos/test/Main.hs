module Main (main) where

import qualified Test.Crypto.VRF.Praos (tests)
import Test.Tasty

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup "praos"
    [ Test.Crypto.VRF.Praos.tests
    ]
