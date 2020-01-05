#pragma once

#include "location.hh"
#include "utils.h"
#include <map>
#include <string>
#include <vector>

#include "types.h"

namespace bpftrace {
namespace ast {

class Visitor;

class Node {
public:
  virtual ~Node() { }
  virtual void accept(Visitor &v) = 0;
  location loc;
  Node() : loc(location()){};
  Node(location loc) : loc(loc){};
};

class Map;
class Variable;
class Expression : public Node {
public:
  SizedType type;
  Map *key_for_map = nullptr;
  Map *map = nullptr; // Only set when this expression is assigned to a map
  Variable *var = nullptr; // Set when this expression is assigned to a variable
  bool is_literal = false;
  bool is_variable = false;
  bool is_map = false;
  Expression() : Node(){};
  Expression(location loc) : Node(loc){};
  // NB: do not free any of the non-owned pointers we store
  virtual ~Expression() = default;
};
using ExpressionList = std::vector<std::unique_ptr<Expression>>;

class Integer : public Expression {
public:
  explicit Integer(long n) : n(n) { is_literal = true; }
  explicit Integer(long n, location loc) : Expression(loc), n(n) { is_literal = true; }
  long n;

  void accept(Visitor &v) override;
};

class PositionalParameter : public Expression {
public:
  explicit PositionalParameter(PositionalParameterType ptype, long n) : ptype(ptype), n(n) {}
  explicit PositionalParameter(PositionalParameterType ptype, long n, location loc) : Expression(loc), ptype(ptype), n(n) {}
  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;

  void accept(Visitor &v) override;
};

class String : public Expression {
public:
  explicit String(std::string str) : str(str) { is_literal = true; }
  explicit String(std::string str, location loc) : Expression(loc), str(str) { is_literal = true; }
  std::string str;

  void accept(Visitor &v) override;
};

class StackMode : public Expression {
public:
  explicit StackMode(std::string mode) : mode(mode) { is_literal = true; }
  explicit StackMode(std::string mode, location loc) : Expression(loc), mode(mode)
    { is_literal = true; }
  std::string mode;

  void accept(Visitor &v) override;
};

class Identifier : public Expression {
public:
  explicit Identifier(std::string ident) : ident(ident) {}
  explicit Identifier(std::string ident, location loc) : Expression(loc), ident(ident) {}
  std::string ident;

  void accept(Visitor &v) override;
};

class Builtin : public Expression {
public:
  explicit Builtin(std::string ident) : ident(is_deprecated(ident)) { }
  explicit Builtin(std::string ident, location loc) : Expression(loc), ident(is_deprecated(ident)) { }
  std::string ident;
  int probe_id;

  void accept(Visitor &v) override;
};

class Call : public Expression {
public:
  explicit Call(std::string &func) : func(is_deprecated(func)), vargs(nullptr) { }
  explicit Call(std::string &func, location loc) : Expression(loc), func(is_deprecated(func)), vargs(nullptr) { }
  Call(std::string &func, std::unique_ptr<ExpressionList> vargs)
      : func(is_deprecated(func)), vargs(std::move(vargs))
  {
  }
  Call(std::string &func, std::unique_ptr<ExpressionList> vargs, location loc)
      : Expression(loc), func(is_deprecated(func)), vargs(std::move(vargs))
  {
  }
  ~Call() = default;
  std::string func;
  std::unique_ptr<ExpressionList> vargs;

  void accept(Visitor &v) override;
};

class Map : public Expression {
public:
  explicit Map(std::string &ident, location loc) : Expression(loc), ident(ident), vargs(nullptr) { is_map = true; }
  Map(std::string &ident, std::unique_ptr<ExpressionList> vargs)
      : ident(ident), vargs(std::move(vargs))
  {
    is_map = true;
  }
  Map(std::string &ident, std::unique_ptr<ExpressionList> vargs, location loc)
      : Expression(loc), ident(ident), vargs(std::move(vargs))
  {
    is_map = true;
    for (auto &expr : *vargs)
    {
      expr->key_for_map = this;
    }
  }
  ~Map() = default;
  std::string ident;
  std::unique_ptr<ExpressionList> vargs;
  bool skip_key_validation = false;

  void accept(Visitor &v) override;
};

class Variable : public Expression {
public:
  explicit Variable(std::string &ident) : ident(ident) { is_variable = true; }
  explicit Variable(std::string &ident, location loc) : Expression(loc), ident(ident) { is_variable = true; }
  std::string ident;

  void accept(Visitor &v) override;
};

class Binop : public Expression {
public:
  Binop(std::unique_ptr<Expression> left,
        int op,
        std::unique_ptr<Expression> right,
        location loc)
      : Expression(loc), left(std::move(left)), right(std::move(right)), op(op)
  {
  }
  ~Binop() = default;
  std::unique_ptr<Expression> left;
  std::unique_ptr<Expression> right;
  int op;

  void accept(Visitor &v) override;
};

class Unop : public Expression {
public:
  Unop(int op, std::unique_ptr<Expression> expr, location loc = location())
      : Expression(loc), expr(std::move(expr)), op(op), is_post_op(false)
  {
  }
  Unop(int op,
       std::unique_ptr<Expression> expr,
       bool is_post_op = false,
       location loc = location())
      : Expression(loc), expr(std::move(expr)), op(op), is_post_op(is_post_op)
  {
  }
  ~Unop() = default;
  std::unique_ptr<Expression> expr;
  int op;
  bool is_post_op;

  void accept(Visitor &v) override;
};

class FieldAccess : public Expression {
public:
  FieldAccess(std::unique_ptr<Expression> expr, const std::string &field)
      : expr(std::move(expr)), field(field)
  {
  }
  FieldAccess(std::unique_ptr<Expression> expr,
              const std::string &field,
              location loc)
      : Expression(loc), expr(std::move(expr)), field(field)
  {
  }
  ~FieldAccess() = default;
  std::unique_ptr<Expression> expr;
  std::string field;

  void accept(Visitor &v) override;
};

class ArrayAccess : public Expression {
public:
  ArrayAccess(std::unique_ptr<Expression> expr,
              std::unique_ptr<Expression> indexpr)
      : expr(std::move(expr)), indexpr(std::move(indexpr))
  {
  }
  ArrayAccess(std::unique_ptr<Expression> expr,
              std::unique_ptr<Expression> indexpr,
              location loc)
      : Expression(loc), expr(std::move(expr)), indexpr(std::move(indexpr))
  {
  }
  ~ArrayAccess() = default;
  std::unique_ptr<Expression> expr;
  std::unique_ptr<Expression> indexpr;

  void accept(Visitor &v) override;
};

class Cast : public Expression {
public:
  Cast(const std::string &type,
       bool is_pointer,
       std::unique_ptr<Expression> expr)
      : cast_type(type), is_pointer(is_pointer), expr(std::move(expr))
  {
  }
  Cast(const std::string &type,
       bool is_pointer,
       std::unique_ptr<Expression> expr,
       location loc)
      : Expression(loc),
        cast_type(type),
        is_pointer(is_pointer),
        expr(std::move(expr))
  {
  }
  std::string cast_type;
  bool is_pointer;
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class Statement : public Node {
public:
  Statement() {}
  Statement(location loc) : Node(loc) {}
};
using StatementList = std::vector<std::unique_ptr<Statement>>;

class ExprStatement : public Statement {
public:
  explicit ExprStatement(std::unique_ptr<Expression> expr)
      : expr(std::move(expr))
  {
  }
  explicit ExprStatement(std::unique_ptr<Expression> expr, location loc)
      : Statement(loc), expr(std::move(expr))
  {
  }
  ~ExprStatement() = default;
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class AssignMapStatement : public Statement {
public:
  AssignMapStatement(std::unique_ptr<Map> map,
                     std::unique_ptr<Expression> expr,
                     location loc = location())
      : Statement(loc), map(std::move(map)), expr(std::move(expr))
  {
    expr->map = map.get();
  };
  ~AssignMapStatement() = default;
  std::unique_ptr<Map> map;
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class AssignVarStatement : public Statement {
public:
  AssignVarStatement(std::unique_ptr<Variable> var, std::unique_ptr<Expression> expr)
      : var(std::move(var)), expr(std::move(expr))
  {
    expr->var = var.get();
  }
  AssignVarStatement(std::unique_ptr<Variable> var,
                     std::unique_ptr<Expression> expr,
                     location loc)
      : Statement(loc), var(std::move(var)), expr(std::move(expr))
  {
    expr->var = var.get();
  }
  ~AssignVarStatement() = default;
  std::unique_ptr<Variable> var;
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class If : public Statement {
public:
  If(std::unique_ptr<Expression> cond, std::unique_ptr<StatementList> stmts)
      : cond(std::move(cond)), stmts(std::move(stmts))
  {
  }
  If(std::unique_ptr<Expression> cond,
     std::unique_ptr<StatementList> stmts,
     std::unique_ptr<StatementList> else_stmts)
      : cond(std::move(cond)),
        stmts(std::move(stmts)),
        else_stmts(std::move(else_stmts))
  {
  }
  ~If() = default;
  std::unique_ptr<Expression> cond;
  std::unique_ptr<StatementList> stmts;
  std::unique_ptr<StatementList> else_stmts;

  void accept(Visitor &v) override;
};

class Unroll : public Statement {
public:
  Unroll(long int var, std::unique_ptr<StatementList> stmts)
      : var(var), stmts(std::move(stmts))
  {
  }
  ~Unroll() = default;
  long int var = 0;
  std::unique_ptr<StatementList> stmts;

  void accept(Visitor &v) override;
};

class Predicate : public Node {
public:
  explicit Predicate(std::unique_ptr<Expression> expr) : expr(std::move(expr))
  {
  }
  explicit Predicate(std::unique_ptr<Expression> expr, location loc)
      : Node(loc), expr(std::move(expr))
  {
  }
  ~Predicate() = default;
  std::unique_ptr<Expression> expr;

  void accept(Visitor &v) override;
};

class Ternary : public Expression {
public:
  Ternary(std::unique_ptr<Expression> cond,
          std::unique_ptr<Expression> left,
          std::unique_ptr<Expression> right)
      : cond(std::move(cond)), left(std::move(left)), right(std::move(right))
  {
  }
  Ternary(std::unique_ptr<Expression> cond,
          std::unique_ptr<Expression> left,
          std::unique_ptr<Expression> right,
          location loc)
      : Expression(loc),
        cond(std::move(cond)),
        left(std::move(left)),
        right(std::move(right))
  {
  }
  ~Ternary();
  std::unique_ptr<Expression> cond;
  std::unique_ptr<Expression> left;
  std::unique_ptr<Expression> right;

  void accept(Visitor &v) override;
};

class AttachPoint : public Node {
public:
  explicit AttachPoint(const std::string &provider, location loc=location())
    : Node(loc), provider(probetypeName(provider)) { }
  AttachPoint(const std::string &provider,
              const std::string &func,
              location loc=location())
    : Node(loc), provider(probetypeName(provider)), func(func), need_expansion(true) { }
  AttachPoint(const std::string &provider,
              const std::string &target,
              const std::string &func,
              bool need_expansion,
              location loc=location())
    : Node(loc), provider(probetypeName(provider)), target(target), func(func), need_expansion(need_expansion) { }
  AttachPoint(const std::string &provider,
              const std::string &target,
              const std::string &ns,
              const std::string &func,
              bool need_expansion,
              location loc=location())
    : Node(loc), provider(probetypeName(provider)), target(target), ns(ns), func(func), need_expansion(need_expansion) { }
  AttachPoint(const std::string &provider,
              const std::string &target,
              uint64_t val,
              location loc=location())
    : Node(loc), provider(probetypeName(provider)), target(target), need_expansion(true)
  {
    if (this->provider == "uprobe" || this->provider == "uretprobe")
      address = val;
    else
      freq = val;
  }
  AttachPoint(const std::string &provider,
              const std::string &target,
              uint64_t addr,
              uint64_t len,
              const std::string &mode,
              location loc=location())
    : Node(loc), provider(probetypeName(provider)), target(target), addr(addr), len(len), mode(mode) { }
  AttachPoint(const std::string &provider,
              const std::string &target,
              const std::string &func,
              uint64_t offset,
              location loc=location())
    : Node(loc), provider(probetypeName(provider)), target(target), func(func), need_expansion(true), func_offset(offset) { }

  std::string provider;
  std::string target;
  std::string ns;
  std::string func;
  usdt_probe_entry usdt; // resolved USDT entry, used to support arguments with wildcard matches
  int freq = 0;
  uint64_t addr = 0;
  uint64_t len = 0;
  std::string mode;
  bool need_expansion = false;
  uint64_t address = 0;
  uint64_t func_offset = 0;

  void accept(Visitor &v) override;
  std::string name(const std::string &attach_point) const;

  int index(std::string name);
  void set_index(std::string name, int index);
private:
  std::map<std::string, int> index_;
};
using AttachPointList = std::vector<std::unique_ptr<AttachPoint>>;

class Probe : public Node {
public:
  Probe(std::unique_ptr<AttachPointList> attach_points,
        std::unique_ptr<Predicate> pred,
        std::unique_ptr<StatementList> stmts)
      : attach_points(std::move(attach_points)),
        pred(std::move(pred)),
        stmts(std::move(stmts))
  {
  }
  ~Probe() = default;

  std::unique_ptr<AttachPointList> attach_points;
  std::unique_ptr<Predicate> pred;
  std::unique_ptr<StatementList> stmts;

  void accept(Visitor &v) override;
  std::string name() const;
  bool need_expansion = false;        // must build a BPF program per wildcard match
  bool need_tp_args_structs = false;  // must import struct for tracepoints

  int index();
  void set_index(int index);
private:
  int index_ = 0;
};
using ProbeList = std::vector<std::unique_ptr<Probe>>;

class Program : public Node {
public:
  Program(const std::string &c_definitions, std::unique_ptr<ProbeList> probes)
      : c_definitions(c_definitions), probes(std::move(probes))
  {
  }
  ~Program() = default;
  std::string c_definitions;
  std::unique_ptr<ProbeList> probes;

  void accept(Visitor &v) override;
};

class Visitor {
public:
  virtual ~Visitor() { }
  virtual void visit(Integer &integer) = 0;
  virtual void visit(PositionalParameter &integer) = 0;
  virtual void visit(String &string) = 0;
  virtual void visit(Builtin &builtin) = 0;
  virtual void visit(Identifier &identifier) = 0;
  virtual void visit(StackMode &mode) = 0;
  virtual void visit(Call &call) = 0;
  virtual void visit(Map &map) = 0;
  virtual void visit(Variable &var) = 0;
  virtual void visit(Binop &binop) = 0;
  virtual void visit(Unop &unop) = 0;
  virtual void visit(Ternary &ternary) = 0;
  virtual void visit(FieldAccess &acc) = 0;
  virtual void visit(ArrayAccess &arr) = 0;
  virtual void visit(Cast &cast) = 0;
  virtual void visit(ExprStatement &expr) = 0;
  virtual void visit(AssignMapStatement &assignment) = 0;
  virtual void visit(AssignVarStatement &assignment) = 0;
  virtual void visit(If &if_block) = 0;
  virtual void visit(Unroll &unroll) = 0;
  virtual void visit(Predicate &pred) = 0;
  virtual void visit(AttachPoint &ap) = 0;
  virtual void visit(Probe &probe) = 0;
  virtual void visit(Program &program) = 0;
};

std::string opstr(Binop &binop);
std::string opstr(Unop &unop);

} // namespace ast
} // namespace bpftrace
