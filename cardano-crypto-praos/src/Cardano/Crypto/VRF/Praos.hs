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
  (
  -- * VRFAlgorithm API
    PraosVRF

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
  , outputBytes
  , proofBytes
  , skBytes
  , pkBytes
  , skToPK
  , skToSeed

  -- * Core VRF operations
  , prove
  , verify
  
  , SignKeyVRF (..)
  , VerKeyVRF (..)
  , CertVRF (..)
  )
where

import Cardano.Binary
  ( FromCBOR (..)
  , ToCBOR (..)
  , serialize'
  )

import Cardano.Crypto.VRF.Class
import Cardano.Prelude (NoUnexpectedThunks, UseIsNormalForm(..))
import Cardano.Crypto.Seed (getBytesFromSeedT)
import GHC.Generics (Generic)
import Data.Coerce (coerce)

import Foreign.ForeignPtr
import Foreign.C.Types
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Utils
-- import Foreign.Storable
import System.IO.Unsafe (unsafePerformIO)
import Control.Monad (void)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Maybe (isJust)

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

-- | A random seed, used to derive a public/secret key pair.
newtype Seed = Seed { unSeed :: ForeignPtr SeedValue }

-- | Secret key. In this implementation, the secret key is actually a 64-byte
-- value that contains both the 32-byte secret key and the corresponding
-- 32-byte public key.
newtype SK = SK { unSK :: ForeignPtr SKValue }
  deriving (Generic)

-- | Public key.
newtype PK = PK { unPK :: ForeignPtr PKValue }
  deriving (Generic)

-- | A proof, as constructed by the 'prove' function.
newtype Proof = Proof { unProof :: ForeignPtr ProofValue }
  deriving (Generic)

-- | Hashed output of a proof verification, as returned by the 'verify'
-- function.
newtype Output = Output { unOutput :: ForeignPtr OutputValue }
  deriving (Generic)

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

-- Key size constants

certSizeVRF :: Int
certSizeVRF = fromIntegral crypto_vrf_proofbytes

signKeySizeVRF :: Int
signKeySizeVRF = fromIntegral crypto_vrf_secretkeybytes

verKeySizeVRF :: Int
verKeySizeVRF = fromIntegral crypto_vrf_publickeybytes

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

seedFromBytes :: ByteString -> Seed
seedFromBytes bs | BS.length bs < fromIntegral crypto_vrf_seedbytes =
  error "Not enough bytes for seed"
seedFromBytes bs = unsafePerformIO $ do
  seed <- mkSeed
  withForeignPtr (unSeed seed) $ \ptr ->
    BS.useAsCString bs $ \cstr ->
      copyBytes (castPtr ptr) cstr (fromIntegral crypto_vrf_seedbytes)
  return seed

-- | Convert an opaque 'Seed' into a 'ByteString' that we can inspect. Note
-- that this will leak the seed into unprotected memory.
unsafeRawSeed :: Seed -> IO ByteString
unsafeRawSeed (Seed fp) = withForeignPtr fp $ \ptr ->
  BS.packCStringLen (castPtr ptr, fromIntegral crypto_vrf_seedbytes)

-- | Convert a proof verification output hash into a 'ByteString' that we can
-- inspect.
outputBytes :: Output -> ByteString
outputBytes (Output op) = unsafePerformIO $ withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, fromIntegral crypto_vrf_outputbytes)

-- | Convert a proof into a 'ByteString' that we can inspect.
proofBytes :: Proof -> ByteString
proofBytes (Proof op) = unsafePerformIO $ withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, certSizeVRF)

-- | Convert a public key into a 'ByteString' that we can inspect.
pkBytes :: PK -> ByteString
pkBytes (PK op) = unsafePerformIO $ withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, verKeySizeVRF)

-- | Convert a public key into a 'ByteString' that we can inspect.
skBytes :: SK -> ByteString
skBytes (SK op) = unsafePerformIO $ withForeignPtr op $ \ptr ->
  BS.packCStringLen (castPtr ptr, signKeySizeVRF)

instance Show Proof where
  show = show . proofBytes

instance Eq Proof where
  a == b = proofBytes a == proofBytes b

instance ToCBOR Proof where
  toCBOR = toCBOR . proofBytes

instance FromCBOR Proof where
  fromCBOR = proofFromBytes <$> fromCBOR


instance Show SK where
  show = show . skBytes

instance Eq SK where
  a == b = skBytes a == skBytes b

instance ToCBOR SK where
  toCBOR = toCBOR . skBytes

instance FromCBOR SK where
  fromCBOR = skFromBytes <$> fromCBOR


instance Show PK where
  show = show . pkBytes

instance Eq PK where
  a == b = pkBytes a == pkBytes b

instance ToCBOR PK where
  toCBOR = toCBOR . pkBytes

instance FromCBOR PK where
  fromCBOR = pkFromBytes <$> fromCBOR

-- | Allocate a Public Key and attach a finalizer. The allocated memory will
-- not be initialized.
mkPK :: IO PK
mkPK = fmap PK $ newForeignPtr finalizerFree =<< mallocBytes verKeySizeVRF

-- | Allocate a Secret Key and attach a finalizer. The allocated memory will
-- not be initialized.
mkSK :: IO SK
mkSK = fmap SK $ newForeignPtr finalizerFree =<< mallocBytes signKeySizeVRF

-- | Allocate a Proof and attach a finalizer. The allocated memory will
-- not be initialized.
mkProof :: IO Proof
mkProof = fmap Proof $ newForeignPtr finalizerFree =<< mallocBytes (certSizeVRF)

proofFromBytes :: ByteString -> Proof
proofFromBytes bs
  | BS.length bs /= certSizeVRF
  = error "Invalid proof length"
  | otherwise
  = unsafePerformIO $ do
      proof <- mkProof
      withForeignPtr (unProof proof) $ \ptr ->
        BS.useAsCString bs $ \cstr -> do
          copyBytes cstr (castPtr ptr) (certSizeVRF)
      return proof

skFromBytes :: ByteString -> SK
skFromBytes bs
  | BS.length bs /= signKeySizeVRF
  = error "Invalid sk length"
  | otherwise
  = unsafePerformIO $ do
      sk <- mkSK
      withForeignPtr (unSK sk) $ \ptr ->
        BS.useAsCString bs $ \cstr -> do
          copyBytes cstr (castPtr ptr) signKeySizeVRF
      return sk

pkFromBytes :: ByteString -> PK
pkFromBytes bs
  | BS.length bs /= verKeySizeVRF
  = error "Invalid pk length"
  | otherwise
  = unsafePerformIO $ do
      pk <- mkPK
      withForeignPtr (unPK pk) $ \ptr ->
        BS.useAsCString bs $ \cstr -> do
          copyBytes cstr (castPtr ptr) verKeySizeVRF
      return pk

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

instance VRFAlgorithm PraosVRF where
  newtype VerKeyVRF PraosVRF = VerKeyPraosVRF PK
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR)
    deriving NoUnexpectedThunks via UseIsNormalForm (ForeignPtr PKValue)

  newtype SignKeyVRF PraosVRF = SignKeyPraosVRF SK
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR)
    deriving NoUnexpectedThunks via UseIsNormalForm (ForeignPtr SKValue)

  newtype CertVRF PraosVRF = CertPraosVRF Proof
    deriving stock   (Show, Eq, Generic)
    deriving newtype (ToCBOR, FromCBOR)
    deriving NoUnexpectedThunks via UseIsNormalForm (ForeignPtr ProofValue)

  type Signable PraosVRF = ToCBOR

  algorithmNameVRF = const "PraosVRF"

  deriveVerKeyVRF = coerce skToPK

  evalVRF = \_ msg (SignKeyPraosVRF sk) -> do
    let msgBS = serialize' msg
    proof <- maybe (error "Invalid Key") pure $ prove sk msgBS
    output <- maybe (error "Invalid Proof") pure $ verify (skToPK sk) proof msgBS
    return (outputBytes output, CertPraosVRF proof)

  verifyVRF = \_ (VerKeyPraosVRF pk) msg (_, CertPraosVRF proof) ->
    isJust $ verify pk proof (serialize' msg)

  -- TODO: verify that the below sizes are correct
  maxVRF _ = 2 ^ (8 * crypto_vrf_proofbytes) - 1
  seedSizeVRF _ = fromIntegral crypto_vrf_seedbytes

  genKeyPairVRF = \cryptoseed ->
    let seed = seedFromBytes . fst . getBytesFromSeedT (fromIntegral crypto_vrf_seedbytes) $ cryptoseed
        (pk, sk) = keypairFromSeed seed
    in (SignKeyPraosVRF sk, VerKeyPraosVRF pk)

  rawSerialiseVerKeyVRF (VerKeyPraosVRF pk) = pkBytes pk
  rawSerialiseSignKeyVRF (SignKeyPraosVRF sk) = skBytes sk
  rawSerialiseCertVRF (CertPraosVRF proof) = proofBytes proof
  rawDeserialiseVerKeyVRF = fmap (VerKeyPraosVRF . pkFromBytes) . assertLength verKeySizeVRF
  rawDeserialiseSignKeyVRF = fmap (SignKeyPraosVRF . skFromBytes) . assertLength signKeySizeVRF
  rawDeserialiseCertVRF = fmap (CertPraosVRF . proofFromBytes) . assertLength certSizeVRF

  sizeVerKeyVRF _ = fromIntegral verKeySizeVRF
  sizeSignKeyVRF _ = fromIntegral signKeySizeVRF
  sizeCertVRF _ = fromIntegral certSizeVRF

assertLength :: Int -> ByteString -> Maybe ByteString
assertLength l bs
  | BS.length bs == l
  = Just bs
  | otherwise
  = Nothing
