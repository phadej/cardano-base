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
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE LambdaCase #-}

-- | Mock implementations of verifiable random functions.
module Cardano.Crypto.VRF.Praos
  ( PraosVRF

  -- * Low-level size specifiers
  --
  -- Sizes of various value types involved in the VRF calculations. Users of
  -- this module will not need these, we are only exporting them for unit
  -- testing purposes.
  , crypto_vrf_proofbytes
  , crypto_vrf_publickeybytes
  , crypto_vrf_secretkeybytes
  , crypto_vrf_seedbytes
  , crypto_vrf_outputbytes

  -- * Value types
  --
  -- These types are all implemented as transparent references. The actual
  -- values are kept entirely in C memory, allocated when a value is created,
  -- and freed when the value's finalizer runs.
  , Seed
  , SK
  , PK
  , Proof
  , Output


  -- * Seed and key generation
  , genSeed
  , keypairFromSeed

  -- * Conversions
  , unsafeRawSeed
  , outputToByteString
  , skToPK
  , skToSeed

  -- * Core VRF operations
  , prove
  , verify
  )
where

-- import Cardano.Binary
--   ( Encoding
--   , FromCBOR (..)
--   , ToCBOR (..)
--   , encodeListLen
--   , enforceSize
--   )

-- import Cardano.Crypto.VRF.Class
-- import Cardano.Prelude (NoUnexpectedThunks, UseIsNormalForm(..))
-- import Crypto.Random (MonadRandom (..))
-- import Data.Proxy (Proxy (..))
-- import GHC.Generics (Generic)
-- import Numeric.Natural (Natural)

import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Marshal.Alloc
-- import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)
import Control.Monad (void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

-- Value types.
--
-- These are all transparent to the Haskell side of things, all we ever do
-- with these is pass pointers to them around. We don't want to know anything
-- about them, hence, we make them uninhabited (isomorphic with
-- 'Data.Void.Void'). The reason we have them at all, rather than duplicating
-- C's void pointers, is because we want to distinguish them at the type
-- level.

data SeedValue
data SKValue
data PKValue
data ProofValue
data OutputValue

-- Type aliases for raw pointers
--
-- These will not leave this module, they are only here for our convenience,
-- so we can afford to not newtype them.

type SeedPtr = Ptr SeedValue
type SKPtr = Ptr SKValue
type PKPtr = Ptr PKValue
type ProofPtr = Ptr ProofValue
type OutputPtr = Ptr OutputValue

-- The exported types.
--
-- These are wrappers around 'ForeignPtr's; we don't export the constructors,
-- so callers have to go through our blessed API to create any of them. This
-- way we can make sure that we always allocate the correct sizes, and attach
-- finalizers that automatically free the memory for us.
newtype Seed = Seed { unSeed :: ForeignPtr SeedValue }
newtype SK = SK { unSK :: ForeignPtr SKValue }
newtype PK = PK { unPK :: ForeignPtr PKValue }
newtype Proof = Proof { unProof :: ForeignPtr ProofValue }
newtype Output = Output { unOutput :: ForeignPtr OutputValue }

-- Raw low-level FFI bindings.
--
foreign import ccall "crypto_vrf_proofbytes" crypto_vrf_proofbytes :: CSize
foreign import ccall "crypto_vrf_publickeybytes" crypto_vrf_publickeybytes :: CSize
foreign import ccall "crypto_vrf_secretkeybytes" crypto_vrf_secretkeybytes :: CSize
foreign import ccall "crypto_vrf_seedbytes" crypto_vrf_seedbytes :: CSize
foreign import ccall "crypto_vrf_outputbytes" crypto_vrf_outputbytes :: CSize

foreign import ccall "crypto_vrf_keypair_from_seed" crypto_vrf_keypair_from_seed :: PKPtr -> SKPtr -> SeedPtr -> IO CInt
foreign import ccall "crypto_vrf_sk_to_pk" crypto_vrf_sk_to_pk :: PKPtr -> SKPtr -> IO CInt
foreign import ccall "crypto_vrf_sk_to_seed" crypto_vrf_sk_to_seed :: SeedPtr -> SKPtr -> IO CInt
foreign import ccall "crypto_vrf_prove" crypto_vrf_prove :: ProofPtr -> SKPtr -> Ptr CChar -> CULLong -> IO CInt
foreign import ccall "crypto_vrf_verify" crypto_vrf_verify :: OutputPtr -> PKPtr -> ProofPtr -> Ptr CChar -> CULLong -> IO CInt

foreign import ccall "randombytes_buf" randombytes_buf :: Ptr a -> CSize -> IO ()

-- | Allocate a 'Seed' and attach a finalizer. The allocated memory will not be initialized.
mkSeed :: IO Seed
mkSeed = do
  ptr <- mallocBytes (fromIntegral crypto_vrf_seedbytes)
  Seed <$> newForeignPtr finalizerFree ptr

-- | Generate a random seed.
-- Uses 'randombytes_buf' to create random data.
genSeed :: IO Seed
genSeed = do
  seed <- mkSeed
  withForeignPtr (unSeed seed) $ \ptr ->
    randombytes_buf ptr crypto_vrf_seedbytes
  return seed

-- | Convert an opaque 'Seed' into a 'ByteString' that we can inspect. Note
-- that this will leak the seed into unprotected memory.
unsafeRawSeed :: Seed -> IO ByteString
unsafeRawSeed (Seed fp) = withForeignPtr fp $ \ptr ->
  BS.packCStringLen (castPtr ptr, fromIntegral crypto_vrf_seedbytes)

-- | Convert a proof verification output hash into a 'ByteString' that we can
-- inspect.
outputToByteString :: Output -> IO ByteString
outputToByteString (Output op) = withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, fromIntegral crypto_vrf_outputbytes)

-- | Allocate a Public Key and attach a finalizer. The allocated memory will
-- not be initialized.
mkPK :: IO PK
mkPK = fmap PK $ newForeignPtr finalizerFree =<< mallocBytes (fromIntegral crypto_vrf_publickeybytes)

-- | Allocate a Secret Key and attach a finalizer. The allocated memory will
-- not be initialized.
mkSK :: IO SK
mkSK = fmap SK $ newForeignPtr finalizerFree =<< mallocBytes (fromIntegral crypto_vrf_secretkeybytes)

-- | Allocate a Proof and attach a finalizer. The allocated memory will
-- not be initialized.
mkProof :: IO Proof
mkProof = fmap Proof $ newForeignPtr finalizerFree =<< mallocBytes (fromIntegral crypto_vrf_proofbytes)

-- | Allocate an Output and attach a finalizer. The allocated memory will
-- not be initialized.
mkOutput :: IO Output
mkOutput = fmap Output $ newForeignPtr finalizerFree =<< mallocBytes (fromIntegral crypto_vrf_outputbytes)

-- | Derive a Public/Secret key pair from a seed.
keypairFromSeed :: Seed -> (PK, SK)
keypairFromSeed seed =
  unsafePerformIO $ withForeignPtr (unSeed seed) $ \sptr -> do
    pk <- mkPK
    sk <- mkSK
    withForeignPtr (unPK pk) $ \pkPtr -> do
      withForeignPtr (unSK sk) $ \skPtr -> do
        void $ crypto_vrf_keypair_from_seed pkPtr skPtr sptr
    return (pk, sk)

-- | Derive a Public Key from a Secret Key.
skToPK :: SK -> PK
skToPK sk =
  unsafePerformIO $ withForeignPtr (unSK sk) $ \skPtr -> do
    pk <- mkPK
    withForeignPtr (unPK pk) $ \pkPtr -> do
      void $ crypto_vrf_sk_to_pk pkPtr skPtr
    return pk

-- | Get the seed used to generate a given Secret Key
skToSeed :: SK -> Seed
skToSeed sk =
  unsafePerformIO $ withForeignPtr (unSK sk) $ \skPtr -> do
    seed <- mkSeed
    _ <- withForeignPtr (unSeed seed) $ \seedPtr -> do
      crypto_vrf_sk_to_seed seedPtr skPtr
    return seed

-- | Construct a proof from a Secret Key and a message.
-- Returns 'Just' the proof on success, 'Nothing' if the secrect key could not
-- be decoded.
prove :: SK -> ByteString -> Maybe Proof
prove sk msg =
  unsafePerformIO $
    withForeignPtr (unSK sk) $ \skPtr -> do
      proof <- mkProof
      BS.useAsCStringLen msg $ \(m, mlen) -> do
        withForeignPtr (unProof proof) $ \proofPtr -> do
          crypto_vrf_prove proofPtr skPtr m (fromIntegral mlen) >>= \case
            0 -> return $ Just proof
            _ -> return Nothing

-- | Verify a VRF proof and validate the Public Key. Returns 'Just' a hash of
-- the verification result on success, 'Nothing' if the verification did not
-- succeed.
--
-- For a given public key and message, there are many possible proofs but only
-- one possible output hash.
verify :: PK -> Proof -> ByteString -> Maybe Output
verify pk proof msg =
  unsafePerformIO $
    withForeignPtr (unPK pk) $ \pkPtr -> do
      withForeignPtr (unProof proof) $ \proofPtr -> do
        output <- mkOutput
        BS.useAsCStringLen msg $ \(m, mlen) -> do
          withForeignPtr (unOutput output) $ \outputPtr -> do
            crypto_vrf_verify outputPtr pkPtr proofPtr m (fromIntegral mlen) >>= \case
              0 -> return $ Just output
              _ -> return Nothing

data PraosVRF


{-

type H = MD5

curve :: C.Curve
curve = C.getCurveByName C.SEC_t113r1

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

h :: Encoding -> Natural
h = fromHash . hashWithSerialiser @H id

h' :: Encoding -> Integer -> Point
h' enc l = pow $ mod (l * (fromIntegral $ h enc)) q

getR :: MonadRandom m => m Integer
getR = generateBetween 0 (q - 1)

instance VRFAlgorithm SimpleVRF where

  type Signable SimpleVRF = ToCBOR

  newtype VerKeyVRF SimpleVRF = VerKeySimpleVRF Point
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR, NoUnexpectedThunks)

  newtype SignKeyVRF SimpleVRF = SignKeySimpleVRF C.PrivateNumber
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR)
    deriving NoUnexpectedThunks via UseIsNormalForm C.PrivateNumber

  data CertVRF SimpleVRF
    = CertSimpleVRF
        { certU :: Point
        , certC :: Natural
        , certS :: Integer
        }
    deriving stock    (Show, Eq, Generic)
    deriving anyclass (NoUnexpectedThunks)

  maxVRF _ = 2 ^ (8 * byteCount (Proxy :: Proxy H)) - 1
  genKeyVRF = SignKeySimpleVRF <$> C.scalarGenerate curve
  deriveVerKeyVRF (SignKeySimpleVRF k) =
    VerKeySimpleVRF $ pow k
  decodeVerKeyVRF = fromCBOR
  encodeVerKeyVRF = toCBOR
  evalVRF () a sk@(SignKeySimpleVRF k) = do
    let u = h' (toCBOR a) k
        y = h $ toCBOR a <> toCBOR u
        VerKeySimpleVRF v = deriveVerKeyVRF sk
    r <- getR
    let c = h $ toCBOR a <> toCBOR v <> toCBOR (pow r) <> toCBOR (h' (toCBOR a) r)
        s = mod (r + k * fromIntegral c) q
    return (y, CertSimpleVRF u c s)
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
    in b1 && c == rhs

instance ToCBOR (CertVRF SimpleVRF) where
  toCBOR cvrf =
    encodeListLen 3 <>
      toCBOR (certU cvrf) <>
      toCBOR (certC cvrf) <>
      toCBOR (certS cvrf)

instance FromCBOR (CertVRF SimpleVRF) where
  fromCBOR =
    CertSimpleVRF <$
      enforceSize "CertVRF SimpleVRF" 3 <*>
      fromCBOR <*>
      fromCBOR <*>
      fromCBOR

-}
