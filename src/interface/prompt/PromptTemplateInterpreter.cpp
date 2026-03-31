#include "interface/prompt/PromptTemplateInterpreter.hpp"
#include "foundation/tools/enum_related.hpp"
#include "foundation/tools/string.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <set>
#include <utility>

namespace AMInterface::prompt {
namespace {

using Node = PromptTemplateNode;
using NodeType = PromptTemplateNodeType;

std::string NormalizeVarKey_(const std::string &raw_key) {
  std::string key = AMStr::lowercase(AMStr::Strip(raw_key));
  if (!key.empty() && key.front() == '$') {
    key.erase(key.begin());
  }
  return key;
}

bool IsIdentifierHead_(char ch) {
  return std::isalpha(static_cast<unsigned char>(ch)) || ch == '_';
}

bool IsIdentifierChar_(char ch) {
  return std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' ||
         ch == '.' || ch == '-' || ch == ':';
}

std::string HighlightErrorAt_(const std::string &source, size_t offset) {
  if (source.empty()) {
    return "[b][/]";
  }
  const size_t index = std::min(offset, source.size() - 1);
  std::string out;
  out.reserve(source.size() + 7);
  out.append(source, 0, index);
  out += "[b]";
  out.push_back(source[index]);
  out += "[/]";
  out.append(source, index + 1, std::string::npos);
  return out;
}

class Parser final {
public:
  explicit Parser(const std::string &source) : source_(source) {}

  PromptTemplateParseResult Parse() {
    PromptTemplateParseResult out;
    out.context.source = source_;
    ParseNodes_(false, &out.context.nodes);
    out.required_vars = std::move(required_vars_);
    out.diagnostics = std::move(diagnostics_);
    return out;
  }

private:
  void AddDiag_(size_t offset, const std::string &message) {
    diagnostics_.items.push_back({offset, message});
  }

  void SkipSpaces_() {
    while (pos_ < source_.size() &&
           std::isspace(static_cast<unsigned char>(source_[pos_]))) {
      ++pos_;
    }
  }

  bool ParseIdentifier_(std::string *name) {
    if (!name || pos_ >= source_.size() || !IsIdentifierHead_(source_[pos_])) {
      return false;
    }
    const size_t start = pos_;
    ++pos_;
    while (pos_ < source_.size() && IsIdentifierChar_(source_[pos_])) {
      ++pos_;
    }
    *name = source_.substr(start, pos_ - start);
    return true;
  }

  bool ParseUntilUnescapedBrace_(size_t begin, size_t *end) const {
    if (!end || begin >= source_.size()) {
      return false;
    }
    size_t p = begin;
    while (p < source_.size()) {
      if (source_[p] == '`') {
        if (p + 1 < source_.size()) {
          p += 2;
          continue;
        }
        ++p;
        continue;
      }
      if (source_[p] == '}') {
        *end = p;
        return true;
      }
      ++p;
    }
    return false;
  }

  void FlushText_(std::string *text, std::vector<Node> *nodes, size_t offset) {
    if (!text || !nodes || text->empty()) {
      return;
    }
    Node node;
    node.type = NodeType::Text;
    node.offset = offset;
    node.text = std::move(*text);
    nodes->push_back(std::move(node));
    text->clear();
  }

  bool ParseDollarVar_(Node *node) {
    if (!node || pos_ >= source_.size() || source_[pos_] != '$') {
      return false;
    }
    const size_t start = pos_;
    ++pos_;
    std::string key;

    if (pos_ < source_.size() && source_[pos_] == '{') {
      ++pos_;
      size_t close = std::string::npos;
      if (!ParseUntilUnescapedBrace_(pos_, &close)) {
        AddDiag_(start, "missing '}' for ${...} variable");
        pos_ = source_.size();
        return false;
      }
      key = source_.substr(pos_, close - pos_);
      pos_ = close + 1;
    } else {
      if (!ParseIdentifier_(&key)) {
        pos_ = start;
        return false;
      }
    }

    key = NormalizeVarKey_(key);
    if (key.empty()) {
      AddDiag_(start, "empty variable name");
      return false;
    }
    required_vars_[key] = std::nullopt;

    node->type = NodeType::Variable;
    node->offset = start;
    node->var_key = std::move(key);
    return true;
  }

  bool ParseBraceVar_(Node *node) {
    if (!node || pos_ + 1 >= source_.size() || source_[pos_] != '{' ||
        source_[pos_ + 1] != '$') {
      return false;
    }
    const size_t start = pos_;
    pos_ += 2;
    size_t close = std::string::npos;
    if (!ParseUntilUnescapedBrace_(pos_, &close)) {
      AddDiag_(start, "missing '}' for {$...} variable");
      pos_ = source_.size();
      return false;
    }

    std::string key = source_.substr(pos_, close - pos_);
    pos_ = close + 1;
    key = NormalizeVarKey_(key);
    if (key.empty()) {
      AddDiag_(start, "empty variable name");
      return false;
    }
    required_vars_[key] = std::nullopt;

    node->type = NodeType::Variable;
    node->offset = start;
    node->var_key = std::move(key);
    return true;
  }

  bool ParseIfBlock_(Node *node) {
    if (!node || pos_ >= source_.size() || source_[pos_] != '{' ||
        source_.compare(pos_, 3, "{if") != 0) {
      return false;
    }

    const size_t start = pos_;
    pos_ += 3;
    SkipSpaces_();

    if (pos_ >= source_.size() || source_[pos_] != '{') {
      AddDiag_(start, "if block missing condition segment");
      pos_ = start + 1;
      return false;
    }

    ++pos_;
    std::vector<Node> cond_nodes;
    ParseNodes_(true, &cond_nodes);

    SkipSpaces_();
    if (pos_ >= source_.size() || source_[pos_] != '{') {
      AddDiag_(start, "if block missing then segment");
      pos_ = std::min(pos_ + 1, source_.size());
      return false;
    }

    ++pos_;
    std::vector<Node> then_nodes;
    ParseNodes_(true, &then_nodes);

    SkipSpaces_();
    std::vector<Node> else_nodes;
    if (pos_ < source_.size() && source_[pos_] == '{') {
      ++pos_;
      ParseNodes_(true, &else_nodes);
      SkipSpaces_();
    }

    if (pos_ < source_.size() && source_[pos_] == '}') {
      ++pos_;
    } else {
      AddDiag_(start, "if block missing closing '}'");
    }

    node->type = NodeType::IfBlock;
    node->offset = start;
    node->cond_nodes = std::move(cond_nodes);
    node->then_nodes = std::move(then_nodes);
    node->else_nodes = std::move(else_nodes);
    return true;
  }

  void ParseNodes_(bool stop_on_brace, std::vector<Node> *nodes) {
    if (!nodes) {
      return;
    }
    std::string text;
    size_t text_offset = pos_;

    auto ensure_text_offset = [&text, &text_offset, this]() {
      if (text.empty()) {
        text_offset = pos_;
      }
    };

    while (pos_ < source_.size()) {
      const char c = source_[pos_];
      if (stop_on_brace && c == '}') {
        FlushText_(&text, nodes, text_offset);
        ++pos_;
        return;
      }

      if (c == '`') {
        ensure_text_offset();
        if (pos_ + 1 < source_.size()) {
          text.push_back(source_[pos_ + 1]);
          pos_ += 2;
        } else {
          text.push_back('`');
          ++pos_;
        }
        continue;
      }

      if (c == '$') {
        Node var_node;
        const size_t before = pos_;
        if (ParseDollarVar_(&var_node)) {
          FlushText_(&text, nodes, text_offset);
          nodes->push_back(std::move(var_node));
          continue;
        }
        ensure_text_offset();
        text.push_back('$');
        if (pos_ == before) {
          ++pos_;
        }
        continue;
      }

      if (c == '{') {
        const size_t before = pos_;
        Node node;
        if (ParseIfBlock_(&node) || ParseBraceVar_(&node)) {
          FlushText_(&text, nodes, text_offset);
          nodes->push_back(std::move(node));
          continue;
        }
        if (pos_ != before) {
          continue;
        }
        ensure_text_offset();
        text.push_back('{');
        ++pos_;
        continue;
      }

      ensure_text_offset();
      text.push_back(c);
      ++pos_;
    }

    FlushText_(&text, nodes, text_offset);
    if (stop_on_brace) {
      AddDiag_(source_.empty() ? 0 : source_.size() - 1, "missing closing '}'");
    }
  }

private:
  const std::string &source_;
  size_t pos_ = 0;
  PromptVarMap required_vars_ = {};
  PromptTemplateDiagnostics diagnostics_ = {};
};

bool IsTruthy_(const std::string &value) {
  const std::string x = AMStr::lowercase(AMStr::Strip(value));
  if (x.empty()) {
    return false;
  }
  return !(x == "0" || x == "false" || x == "no" || x == "off");
}

bool EvaluateExpr_(const std::string &expr) {
  const std::string x = AMStr::Strip(expr);
  if (x.empty()) {
    return false;
  }

  size_t pos = std::string::npos;
  auto has_op = [&x, &pos](const std::string &op) {
    pos = x.find(op);
    return pos != std::string::npos;
  };

  if (has_op("&&")) {
    return EvaluateExpr_(x.substr(0, pos)) && EvaluateExpr_(x.substr(pos + 2));
  }
  if (has_op("||")) {
    return EvaluateExpr_(x.substr(0, pos)) || EvaluateExpr_(x.substr(pos + 2));
  }

  for (const std::string &op : {"==", ">=", "<=", ">", "<"}) {
    if (!has_op(op)) {
      continue;
    }
    const std::string l = AMStr::Strip(x.substr(0, pos));
    const std::string r = AMStr::Strip(x.substr(pos + op.size()));
    char *e1 = nullptr;
    char *e2 = nullptr;
    const double ld = std::strtod(l.c_str(), &e1);
    const double rd = std::strtod(r.c_str(), &e2);
    const bool numeric = (e1 && e2 && *e1 == '\0' && *e2 == '\0');
    if (numeric) {
      if (op == "==") {
        return ld == rd;
      }
      if (op == ">=") {
        return ld >= rd;
      }
      if (op == "<=") {
        return ld <= rd;
      }
      if (op == ">") {
        return ld > rd;
      }
      return ld < rd;
    }

    if (op == "==") {
      return l == r;
    }
    if (op == ">=") {
      return l >= r;
    }
    if (op == "<=") {
      return l <= r;
    }
    if (op == ">") {
      return l > r;
    }
    return l < r;
  }

  return IsTruthy_(x);
}

class Renderer final {
public:
  explicit Renderer(const PromptVarMap &vars) : vars_(vars) {}

  ECMData<std::string> Render(const PromptTemplateContext &context) {
    std::string out;
    RenderNodes_(context.nodes, &out);

    if (!missing_vars_.empty()) {
      std::string msg = "missing variables: ";
      bool first = true;
      for (const auto &name : missing_vars_) {
        if (!first) {
          msg += ", ";
        }
        msg += name;
        first = false;
      }
      return {std::string{}, Err(EC::InvalidArg, msg)};
    }
    return {out, Ok()};
  }

private:
  void RenderNodes_(const std::vector<Node> &nodes, std::string *out) {
    if (!out) {
      return;
    }
    for (const auto &node : nodes) {
      if (node.type == NodeType::Text) {
        *out += node.text;
        continue;
      }
      if (node.type == NodeType::Variable) {
        const auto it = vars_.find(node.var_key);
        if (it == vars_.end() || !it->second.has_value()) {
          missing_vars_.insert(node.var_key);
          continue;
        }
        *out += it->second.value();
        continue;
      }
      if (node.type == NodeType::IfBlock) {
        std::string cond_value;
        RenderNodes_(node.cond_nodes, &cond_value);
        const bool condition = EvaluateExpr_(cond_value);
        if (condition) {
          RenderNodes_(node.then_nodes, out);
        } else {
          RenderNodes_(node.else_nodes, out);
        }
      }
    }
  }

private:
  const PromptVarMap &vars_;
  std::set<std::string> missing_vars_ = {};
};

} // namespace

ECMData<PromptTemplateParseResult>
PromptTemplateInterpreter::Parse(const std::string &input) const {
  Parser parser(input);
  PromptTemplateParseResult result = parser.Parse();
  if (result.diagnostics.HasError()) {
    const auto &diag = result.diagnostics.items.front();
    const size_t index =
        (input.empty() ? static_cast<size_t>(0)
                       : std::min(diag.offset, input.size() - 1));
    const std::string msg = AMStr::fmt(
        "{} at {} of {}", diag.message, index, HighlightErrorAt_(input, index));
    return {std::move(result),
            Err(EC::InvalidArg, msg)};
  }
  return {std::move(result), Ok()};
}

ECMData<std::string>
PromptTemplateInterpreter::Render(const PromptTemplateContext &context,
                                  const PromptVarMap &vars) const {
  Renderer renderer(vars);
  return renderer.Render(context);
}

} // namespace AMInterface::prompt
