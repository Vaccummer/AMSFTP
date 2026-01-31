  // Draft: core interactive loop and helpers.

  // Result returned by DispatchCliCommands (interactive).
  struct DispatchResult {
    ECM rcm;
    bool enter_interactive = false; // optional, for future use
  };

  // Preprocess result.
  enum class PreprocessResult { Continue, Handled, Exit };

  // Holds prompt state across loop iterations.
  struct PromptState {
    ECM last_rcm = {EC::Success, ""};
    std::string last_nickname;
    std::string cached_prefix;
    std::string last_elapsed;
  };

  // Build prompt string. Caches expensive segments if nickname unchanged.
  static std::string BuildPrompt(PromptState &state, AMClientManager &cm,
                                 AMConfigManager &cfg, const std::string &workdir,
                                 const std::string &last_elapsed) {
    // NOTE: sysicon selection uses GetOSType + setting.toml
    std::string nickname =
        cm.CLIENT ? cm.CLIENT->GetNickname() : std::string("local");

    if (nickname != state.last_nickname || state.cached_prefix.empty()) {
      std::string sysicon = cfg.GetSettingString({"prompt", "sysicon"}, "💻");
      std::string username = cm.CLIENT ? cm.CLIENT->GetUserName() : "user";
      std::string hostname = cm.CLIENT ? cm.CLIENT->GetHostName() : "host";
      state.cached_prefix = AMStr::amfmt("{} {}@{}", sysicon, username, hostname);
      state.last_nickname = nickname;
    }

    std::string status = "✅";
    std::string ec_name;
    if (state.last_rcm.first != EC::Success) {
      status = "❌";
      ec_name = std::string(magic_enum::enum_name(state.last_rcm.first));
    }

    std::string line1 = AMStr::amfmt("{}  {}  {} {}",
                                     state.cached_prefix, last_elapsed, status,
                                     ec_name.empty() ? "" : ec_name);
    std::string line2 = AMStr::amfmt("({}){} $", nickname, workdir);
    return line1 + "\n" + line2 + " ";
  }

  // Interactive input function (dedicated replxx handle).
  static bool CorePromptInput(AMPromptManager &pm, const std::string &prompt,
                              std::string *out_line) {
    /** This uses a separate replxx handle managed by PromptManager. */
    // 1) Activate COREPROMPT hook; reset amgif; keep iskill.
    AMCliSignalMonitor::Instance().ResumeHook("COREPROMPT");
    AMCliSignalMonitor::Instance().SilenceHook("GLOBAL");
    amgif->reset();

    bool canceled = pm.PromptCore(prompt, out_line); // placeholder: you implement

    // 2) Check signal flags.
    if (amgif->iskill) {
      // Clean up and exit path handled by caller.
      return false;
    }
    if (amgif->check()) {
      pm.Print("Interrupted. Type 'exit' to quit.");
      // Silence hook and return "no line"
      AMCliSignalMonitor::Instance().SilenceHook("COREPROMPT");
      AMCliSignalMonitor::Instance().ResumeHook("GLOBAL");
      return false;
    }

    // 3) Deactivate COREPROMPT hook.
    AMCliSignalMonitor::Instance().SilenceHook("COREPROMPT");
    AMCliSignalMonitor::Instance().ResumeHook("GLOBAL");
    return !canceled;
  }

  // Preprocess command (aliases, special cases, etc.).
  static PreprocessResult CommandPreprocess(const std::string &line,
                                            std::string *out_line) {
    /** Return Handled if fully processed; Exit if should exit loop. */
    // Example: help, alias expansion, etc.
    *out_line = line;
    return PreprocessResult::Continue;
  }

  // Parse with CLI11 from input line.
  static bool ParseCommand(CLI::App &app, const std::string &line,
                           std::string *error_msg) {
    /** Build argv from line and parse. */
    std::vector[std::string](std::string) argv = SplitToArgv(line); // implement tokenization
    try {
      app.parse(argv);
      return true;
    } catch (const CLI::ParseError &e) {
      if (error_msg) {
        *error_msg = e.what();
      }
      return false;
    }
  }

  // Main interactive loop.
  int RunInteractiveLoop(CLI::App &app, CliArgsPool &args_pool,
                         AMConfigManager &cfg, AMClientManager &cm,
                         AMFileSystem &fs) {
    AMIsInteractive.store(true);

    PromptState prompt_state;
    AMPromptManager &pm = AMPromptManager::Instance();

    while (true) {
      std::string workdir =
          cm.CLIENT ? cm.CLIENT->GetWorkdir() : std::string("/");
      std::string prompt =
          BuildPrompt(prompt_state, cm, cfg, workdir, prompt_state.last_elapsed);

    std::string line;
      if (!CorePromptInput(pm, prompt, &line)) {
        if (amgif->iskill) {
          break;
        }
        continue;
      }

    std::string trimmed = AMStr::Strip(line);
      if (trimmed.empty()) {
        continue;
      }
      std::string lowered = AMStr::lowercase(trimmed);
      if (lowered == "exit") {
        break;
      }

    std::string processed;
      PreprocessResult pre = CommandPreprocess(trimmed, &processed);
      if (pre == PreprocessResult::Exit) {
        break;
      }
      if (pre == PreprocessResult::Handled) {
        continue;
      }

    // Reset CLI11 state each iteration if needed.
      app.clear();
      CliCommands cli_commands = BindCliOptions(app, args_pool);

    std::string parse_error;
      if (!ParseCommand(app, processed, &parse_error)) {
        pm.Print(parse_error);
        continue;
      }

    auto time_start = std::chrono::steady_clock::now();
      DispatchResult result = DispatchCliCommands(cli_commands,
                                                  { /* managers */ });
      auto time_end = std::chrono::steady_clock::now();

    // Update prompt state.
      prompt_state.last_rcm = result.rcm;
      prompt_state.last_elapsed =
          AMStr::amfmt("{}ms",
                       std::chrono::duration_cast[std::chrono::milliseconds](std::chrono::milliseconds)(
                           time_end - time_start)
                           .count());
    }

    return 0;
  }
