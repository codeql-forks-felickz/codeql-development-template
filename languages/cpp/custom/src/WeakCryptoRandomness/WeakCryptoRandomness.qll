/**
 * Provides extensible predicates and classes for modeling cryptographic algorithm
 * selection, RSA padding selection, and non-cryptographic pseudo-random number
 * generators in C and C++ APIs such as the Windows CryptoAPI (`wincrypt.h`).
 *
 * Models are supplied as data extensions (see `weak-crypto-randomness.model.yml`).
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/**
 * Holds if argument `algorithmArg` (0-based) of the global function `function`
 * selects a cryptographic algorithm, for example the `Algid` argument of
 * `CryptCreateHash`.
 */
extensible predicate cryptoAlgorithmArgumentModel(string function, int algorithmArg);

/**
 * Holds if the macro or enum constant named `constant` selects the cryptographic
 * algorithm `algorithm`, which is of kind `kind`. Supported kinds are
 * `weak-cipher`, `weak-hash` and `rsa`.
 */
extensible predicate cryptoAlgorithmConstantModel(string constant, string algorithm, string kind);

/**
 * Holds if the global function `function` encrypts or decrypts with the key
 * passed as argument `keyArg`, and the padding mode is selected by the flags
 * passed as argument `flagsArg`, where setting the bits in `oaepFlag` selects
 * OAEP padding.
 */
extensible predicate rsaPaddingFlagsModel(string function, int keyArg, int flagsArg, int oaepFlag);

/**
 * Holds if the global (or `std`) function `function` is a statistical,
 * non-cryptographic pseudo-random number generator.
 */
extensible predicate weakPrngFunctionModel(string function);

/**
 * An expression that is the expansion of a macro, or an access of an enum
 * constant, that is modeled as selecting a cryptographic algorithm.
 */
class CryptoAlgorithmConstant extends Expr {
  string name;
  string algorithm;
  string kind;

  CryptoAlgorithmConstant() {
    cryptoAlgorithmConstantModel(name, algorithm, kind) and
    (
      exists(MacroInvocation mi | mi.getMacroName() = name and mi.getExpr() = this)
      or
      this.(EnumConstantAccess).getTarget().getName() = name
    )
  }

  /** Gets the name of the macro or enum constant. */
  string getConstantName() { result = name }

  /** Gets the name of the selected algorithm. */
  string getAlgorithm() { result = algorithm }

  /** Gets the kind of the selected algorithm. */
  string getKind() { result = kind }
}

/**
 * Holds if `call` selects the cryptographic algorithm specified by `constant`
 * through a modeled algorithm argument.
 */
predicate selectsCryptoAlgorithm(FunctionCall call, CryptoAlgorithmConstant constant) {
  exists(string function, int algorithmArg |
    cryptoAlgorithmArgumentModel(function, algorithmArg) and
    call.getTarget().hasGlobalName(function) and
    DataFlow::localExprFlow(constant, call.getArgument(algorithmArg))
  )
}

/** A call to a function modeled as a non-cryptographic pseudo-random number generator. */
class WeakPrngCall extends FunctionCall {
  WeakPrngCall() {
    exists(string function |
      weakPrngFunctionModel(function) and
      this.getTarget().hasGlobalOrStdName(function)
    )
  }
}
