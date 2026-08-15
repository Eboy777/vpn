export async function initializePairingWithRecovery(api, store) {
  let state = await store.read();
  try {
    return {state, result: await api.pairingInit(state.deviceId)};
  } catch (error) {
    if (error?.code !== "DEVICE_ALREADY_PAIRED") throw error;
    state = await store.reset({controlRateLimitedUntil: state.controlRateLimitedUntil});
    return {state, result: await api.pairingInit(state.deviceId)};
  }
}
