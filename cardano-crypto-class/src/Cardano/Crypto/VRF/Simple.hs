{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Mock implementations of verifiable random functions.
module Cardano.Crypto.VRF.Simple
  ( SimpleVRF
  , pointFromMaybe
  )
where

import           Data.Proxy (Proxy (..))
import           GHC.Generics (Generic)
import           Numeric.Natural (Natural)

import           Cardano.Prelude (NoUnexpectedThunks, UseIsNormalForm(..))
import           Cardano.Binary (Encoding, FromCBOR (..), ToCBOR (..))

import           Crypto.Number.Generate (generateBetween)
import qualified Crypto.PubKey.ECC.Prim as C
import qualified Crypto.PubKey.ECC.Types as C
import           Crypto.Random (MonadRandom (..))

import           Data.Word
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Bits (shiftL)

import           Cardano.Crypto.Hash
import           Cardano.Crypto.Seed
import           Cardano.Crypto.Util
import           Cardano.Crypto.VRF.Class

data SimpleVRF

type H = MD5

curve :: C.Curve
curve = C.getCurveByName C.SEC_t113r1
-- C.curveSizeBits curve = 113 bits, 15 bytes

q :: Integer
q = C.ecc_n $ C.common_curve curve

newtype Point = Point C.Point
  deriving (Eq, Generic)
  deriving NoUnexpectedThunks via UseIsNormalForm C.Point

instance Show Point where
  show (Point p) = show p

instance ToCBOR Point where
  toCBOR (Point p) = toCBOR $ pointToMaybe p

instance FromCBOR Point where
  fromCBOR = Point . pointFromMaybe <$> fromCBOR

instance Semigroup Point where
  Point p <> Point r = Point $ C.pointAdd curve p r

instance Monoid Point where
  mempty = Point C.PointO
  mappend = (<>)

pointToMaybe :: C.Point -> Maybe (Integer, Integer)
pointToMaybe C.PointO = Nothing
pointToMaybe (C.Point x y) = Just (x, y)

pointFromMaybe :: Maybe (Integer, Integer) -> C.Point
pointFromMaybe Nothing = C.PointO
pointFromMaybe (Just (x, y)) = C.Point x y

pow :: Integer -> Point
pow = Point . C.pointBaseMul curve

pow' :: Point -> Integer -> Point
pow' (Point p) n = Point $ C.pointMul curve n p

h :: Encoding -> ByteString
h = getHash . hashWithSerialiser @H id

h' :: Encoding -> Integer -> Point
h' enc l = pow $ mod (l * (fromIntegral . bsToNat $ h enc)) q

getR :: MonadRandom m => m Integer
getR = generateBetween 0 (q - 1)

-- natToBS :: Natural -> ByteString
-- natToBS 0 = BS.pack [0]
-- natToBS n = BS.pack $ natToBytesBE n
-- 
-- natToBytesBE :: Natural -> [Word8]
-- natToBytesBE = reverse . natToBytesLE
-- 
-- natToBytesLE :: Natural -> [Word8]
-- natToBytesLE 0 = []
-- natToBytesLE n = fromIntegral n : natToBytesLE (n `shiftR` 8)

bsToNat :: ByteString -> Natural
bsToNat = bytesToNatBE . BS.unpack

bytesToNatBE :: [Word8] -> Natural
bytesToNatBE = bytesToNatLE . reverse

bytesToNatLE :: [Word8] -> Natural
bytesToNatLE [] = 0
bytesToNatLE (n:ns) = fromIntegral n + bytesToNatLE ns `shiftL` 8

instance VRFAlgorithm SimpleVRF where

  --
  -- Key and signature types
  --

  newtype VerKeyVRF SimpleVRF = VerKeySimpleVRF Point
    deriving stock   (Show, Eq, Generic)
    deriving newtype (NoUnexpectedThunks)

  newtype SignKeyVRF SimpleVRF = SignKeySimpleVRF C.PrivateNumber
    deriving stock   (Show, Eq, Generic)
    deriving NoUnexpectedThunks via UseIsNormalForm C.PrivateNumber

  data CertVRF SimpleVRF
    = CertSimpleVRF
        { certU :: Point    -- 15 byte point numbers, round up to 16
        , certC :: Natural  -- md5 hash, so 16 bytes
        , certS :: Integer  -- at most q, so 15 bytes, round up to 16
        }
    deriving stock    (Show, Eq, Generic)
    deriving anyclass (NoUnexpectedThunks)

  --
  -- Metadata and basic key operations
  --

  algorithmNameVRF _ = "simple"

  deriveVerKeyVRF (SignKeySimpleVRF k) =
    VerKeySimpleVRF $ pow k

  sizeVerKeyVRF  _ = 32
  sizeSignKeyVRF _ = 16
  sizeCertVRF    _ = 64


  --
  -- Core algorithm operations
  --

  type Signable SimpleVRF = ToCBOR

  evalVRF () a sk@(SignKeySimpleVRF k) = do
    let u = h' (toCBOR a) k
        y = h $ toCBOR a <> toCBOR u
        VerKeySimpleVRF v = deriveVerKeyVRF sk
    r <- getR
    let c = h $ toCBOR a <> toCBOR v <> toCBOR (pow r) <> toCBOR (h' (toCBOR a) r)
        s = mod (r + k * fromIntegral (bsToNat c)) q
    return (y, CertSimpleVRF u (bsToNat c) s)

  verifyVRF () (VerKeySimpleVRF v) a (y, cert) =
    let u = certU cert
        c = certC cert
        c' = -fromIntegral c
        s = certS cert
        b1 = y == h (toCBOR a <> toCBOR u)
        rhs =
          h $ toCBOR a <>
            toCBOR v <>
            toCBOR (pow s <> pow' v c') <>
            toCBOR (h' (toCBOR a) s <> pow' u c')
    in b1 && c == bsToNat rhs

  maxVRF _ = 2 ^ (8 * sizeHash (Proxy :: Proxy H)) - 1


  --
  -- Key generation
  --

  seedSizeVRF _  = 16 * 10 -- size of SEC_t113r1 * up to 10 iterations
  genKeyVRF seed = SignKeySimpleVRF
                     (runMonadRandomWithSeed seed (C.scalarGenerate curve))


  --
  -- raw serialise/deserialise
  --

  -- All the integers here are 15 or 16 bytes big, we round up to 16.

  rawSerialiseVerKeyVRF (VerKeySimpleVRF (Point C.PointO)) =
      error "rawSerialiseVerKeyVRF: Point at infinity"
  rawSerialiseVerKeyVRF (VerKeySimpleVRF (Point (C.Point p1 p2))) =
      writeBinaryNatural 16 (fromInteger p1)
   <> writeBinaryNatural 16 (fromInteger p2)

  rawSerialiseSignKeyVRF (SignKeySimpleVRF sk) =
      writeBinaryNatural 16 (fromInteger sk)

  rawSerialiseCertVRF (CertSimpleVRF (Point C.PointO) _ _) =
      error "rawSerialiseCertVRF: Point at infinity"
  rawSerialiseCertVRF (CertSimpleVRF (Point (C.Point p1 p2)) c s) =
      writeBinaryNatural 16 (fromInteger p1)
   <> writeBinaryNatural 16 (fromInteger p2)
   <> writeBinaryNatural 16 c
   <> writeBinaryNatural 16 (fromInteger s)

  rawDeserialiseVerKeyVRF bs
    | [p1b, p2b] <- splitsAt [16,16] bs
    , let p1 = toInteger (readBinaryNatural p1b)
          p2 = toInteger (readBinaryNatural p2b)
    = Just $! VerKeySimpleVRF (Point (C.Point p1 p2))

    | otherwise
    = Nothing

  rawDeserialiseSignKeyVRF bs
    | [skb] <- splitsAt [16] bs
    , let sk = toInteger (readBinaryNatural skb)
    = Just $! SignKeySimpleVRF sk

    | otherwise
    = Nothing

  rawDeserialiseCertVRF bs
    | [p1b, p2b, cb, sb] <- splitsAt [16,16,16,16] bs
    , let p1 = toInteger (readBinaryNatural p1b)
          p2 = toInteger (readBinaryNatural p2b)
          c  =            readBinaryNatural cb
          s  = toInteger (readBinaryNatural sb)
    = Just $! CertSimpleVRF (Point (C.Point p1 p2)) c s

    | otherwise
    = Nothing

instance ToCBOR (VerKeyVRF SimpleVRF) where
  toCBOR = encodeVerKeyVRF
  encodedSizeExpr _size = encodedVerKeyVRFSizeExpr

instance FromCBOR (VerKeyVRF SimpleVRF) where
  fromCBOR = decodeVerKeyVRF

instance ToCBOR (SignKeyVRF SimpleVRF) where
  toCBOR = encodeSignKeyVRF
  encodedSizeExpr _size = encodedSignKeyVRFSizeExpr

instance FromCBOR (SignKeyVRF SimpleVRF) where
  fromCBOR = decodeSignKeyVRF

instance ToCBOR (CertVRF SimpleVRF) where
  toCBOR = encodeCertVRF
  encodedSizeExpr _size = encodedCertVRFSizeExpr

instance FromCBOR (CertVRF SimpleVRF) where
  fromCBOR = decodeCertVRF

