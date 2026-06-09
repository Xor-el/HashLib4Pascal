/* glibc 2.34+ removed __libc_csu_init / __libc_csu_fini. FPC 3.2.2's
   RTL still references them. Provide empty stubs so the linker
   is satisfied. */
void __libc_csu_init(int argc, char **argv, char **envp) { (void)argc; (void)argv; (void)envp; }
void __libc_csu_fini(void) {}
