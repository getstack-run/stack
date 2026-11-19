/** Encryption contexts that bind authority ciphertexts to their record and store. */
export function proofContext(operatorId: string, proofId: string, version: number, store: string) {
  return { operator_id: operatorId, proof_id: proofId, proof_version: String(version), store };
}

export function bindingContext(
  operatorId: string,
  bindingId: string,
  version: number,
  store: string,
) {
  return {
    operator_id: operatorId,
    binding_id: bindingId,
    binding_version: String(version),
    store,
  };
}
