%skeleton "lalr1.cc"
%require "3.0.4"
%defines
%define api.namespace { bpftrace }
%define parser_class_name { Parser }

%define api.token.constructor
%define api.value.type variant
%define parse.assert

%define parse.error verbose

%param { bpftrace::Driver &driver }
%param { void *yyscanner }
%locations

// Forward declarations of classes referenced in the parser
%code requires
{
namespace bpftrace {
class Driver;
namespace ast {
class Node;
} // namespace ast
} // namespace bpftrace
#include "ast.h"
}

%{
#include <iostream>
#include <memory>

#include "driver.h"

void yyerror(bpftrace::Driver &driver, const char *s);
%}

%token
  END 0      "end of file"
  COLON      ":"
  SEMI       ";"
  LBRACE     "{"
  RBRACE     "}"
  LBRACKET   "["
  RBRACKET   "]"
  LPAREN     "("
  RPAREN     ")"
  QUES       "?"
  ENDPRED    "end predicate"
  COMMA      ","
  PARAMCOUNT "$#"
  ASSIGN     "="
  EQ         "=="
  NE         "!="
  LE         "<="
  GE         ">="
  LEFT       "<<"
  RIGHT      ">>"
  LT         "<"
  GT         ">"
  LAND       "&&"
  LOR        "||"
  PLUS       "+"
  INCREMENT  "++"

  LEFTASSIGN   "<<="
  RIGHTASSIGN  ">>="
  PLUSASSIGN  "+="
  MINUSASSIGN "-="
  MULASSIGN   "*="
  DIVASSIGN   "/="
  MODASSIGN   "%="
  BANDASSIGN  "&="
  BORASSIGN   "|="
  BXORASSIGN  "^="

  MINUS      "-"
  DECREMENT  "--"
  MUL        "*"
  DIV        "/"
  MOD        "%"
  BAND       "&"
  BOR        "|"
  BXOR       "^"
  LNOT       "!"
  BNOT       "~"
  DOT        "."
  PTR        "->"
  IF         "if"
  ELSE       "else"
  UNROLL     "unroll"
  STRUCT     "struct"
  UNION      "union"
;

%token <std::string> BUILTIN "builtin"
%token <std::string> CALL "call"
%token <std::string> CALL_BUILTIN "call_builtin"
%token <std::string> IDENT "identifier"
%token <std::string> PATH "path"
%token <std::string> CPREPROC "preprocessor directive"
%token <std::string> STRUCT_DEFN "struct definition"
%token <std::string> ENUM "enum"
%token <std::string> STRING "string"
%token <std::string> MAP "map"
%token <std::string> VAR "variable"
%token <std::string> PARAM "positional parameter"
%token <long> INT "integer"
%token <long> CINT "colon surrounded integer"
%token <std::string> STACK_MODE "stack_mode"

%type <std::string> c_definitions
%type <std::unique_ptr<ast::ProbeList>> probes
%type <std::unique_ptr<ast::Probe>> probe
%type <std::unique_ptr<ast::Predicate>> pred
%type <std::unique_ptr<ast::Ternary>> ternary
%type <std::unique_ptr<ast::StatementList>> block stmts
%type <std::unique_ptr<ast::Statement>> block_stmt stmt semicolon_ended_stmt compound_assignment
%type <std::unique_ptr<ast::Expression>> expr
%type <std::unique_ptr<ast::Call>> call
%type <std::unique_ptr<ast::Map>> map
%type <std::unique_ptr<ast::Variable>> var
%type <std::unique_ptr<ast::ExpressionList>> vargs
%type <std::unique_ptr<ast::AttachPointList>> attach_points
%type <std::unique_ptr<ast::AttachPoint>> attach_point
%type <std::unique_ptr<ast::PositionalParameter>> param
%type <std::string> wildcard
%type <std::string> ident
%type <std::unique_ptr<ast::Expression>> map_or_var
%type <std::unique_ptr<ast::Expression>> pre_post_op
%type <std::unique_ptr<ast::Integer>> int

%right ASSIGN
%left QUES COLON
%left LOR
%left LAND
%left BOR
%left BXOR
%left BAND
%left EQ NE
%left LE GE LT GT
%left LEFT RIGHT
%left PLUS MINUS
%left MUL DIV MOD
%right LNOT BNOT DEREF CAST
%left DOT PTR

%start program

%%

program : c_definitions probes { driver.root_ = std::make_unique<ast::Program>($1, $2); }
        ;

c_definitions : CPREPROC c_definitions    { $$ = $1 + "\n" + $2; }
              | STRUCT_DEFN c_definitions { $$ = $1 + ";\n" + $2; }
              | ENUM c_definitions        { $$ = $1 + ";\n" + $2; }
              |                           { $$ = std::string(); }
              ;

probes : probes probe { $$ = std::move($1); $$->push_back(std::move($2)); }
       | probe        { $$ = std::make_unique<ast::ProbeList>(); $$->push_back(std::move($1)); }
       ;

probe : attach_points pred block { $$ = std::make_unique<ast::Probe>($1, $2, $3); }
      ;

attach_points : attach_points "," attach_point { $$ = std::move($1); $$->push_back($3); }
              | attach_point                   { $$ = std::make_unique<ast::AttachPointList>(); $$->push_back(std::move($1)); }
              ;

attach_point : ident                            { $$ = std::make_unique<ast::AttachPoint>($1, @$); }
             | ident ":" wildcard               { $$ = std::make_unique<ast::AttachPoint>($1, $3, @$); }
             | ident PATH STRING                { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, false, @$); }
             | ident PATH wildcard              { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, true, @$); }
             | ident PATH wildcard PLUS INT     { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, (uint64_t) $5, @$); }
             | ident PATH STRING PLUS INT       { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, (uint64_t) $5, @$); }
             | ident PATH INT                   { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, @$); }
             | ident PATH INT CINT ident        { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, $4, $5, @$); }
             | ident PATH STRING ":" STRING     { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, $5, false, @$); }
             | ident PATH STRING ":" wildcard   { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, $5, true, @$); }
             | ident PATH wildcard ":" STRING   { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, $5, true, @$); }
             | ident PATH wildcard ":" wildcard { $$ = std::make_unique<ast::AttachPoint>($1, $2.substr(1, $2.size()-2), $3, $5, true, @$); }
             ;

wildcard : wildcard ident    { $$ = $1 + $2; }
         | wildcard MUL      { $$ = $1 + "*"; }
         | wildcard LBRACKET { $$ = $1 + "["; }
         | wildcard RBRACKET { $$ = $1 + "]"; }
         |                   { $$ = ""; }
         ;

pred : DIV expr ENDPRED { $$ = std::make_unique<ast::Predicate>($2, @$); }
     |                  { $$ = nullptr; }
     ;

ternary : expr QUES expr COLON expr { $$ = std::make_unique<ast::Ternary>($1, $3, $5, @$); }
     ;

param : PARAM      { $$ = std::make_unique<ast::PositionalParameter>(PositionalParameterType::positional, std::stoll($1.substr(1, $1.size()-1)), @$); }
      | PARAMCOUNT { $$ = std::make_unique<ast::PositionalParameter>(PositionalParameterType::count, 0, @$); }
      ;

block : "{" stmts "}"     { $$ = std::move($2); }
      ;

semicolon_ended_stmt: stmt ";"  { $$ = std::move($1); }
                    ;

stmts : semicolon_ended_stmt stmts { $$ = std::move($2); $$->insert($$->begin(), $1); }
      | block_stmt stmts           { $$ = std::move($2); $$->insert($$->begin(), $1); }
      | stmt                       { $$ = std::make_unique<ast::StatementList>(); $$->push_back($1); }
      |                            { $$ = std::make_unique<ast::StatementList>(); }
      ;

block_stmt : IF "(" expr ")" block  { $$ = std::make_unique<ast::If>($3, $5); }
           | IF "(" expr ")" block ELSE block { $$ = std::make_unique<ast::If>($3, $5, $7); }
           | UNROLL "(" INT ")" block { $$ = std::make_unique<ast::Unroll>($3, $5); }
           ;

stmt : expr                { $$ = std::make_unique<ast::ExprStatement>($1); }
     | compound_assignment { $$ = std::move($1); }
     | map "=" expr        { $$ = std::make_unique<ast::AssignMapStatement>($1, $3, @2); }
     | var "=" expr        { $$ = std::make_unique<ast::AssignVarStatement>($1, $3, @2); }
     ;

compound_assignment : map LEFTASSIGN expr  { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::LEFT,  $3, @2)); }
                    | var LEFTASSIGN expr  { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::LEFT,  $3, @2)); }
                    | map RIGHTASSIGN expr { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::RIGHT, $3, @2)); }
                    | var RIGHTASSIGN expr { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::RIGHT, $3, @2)); }
                    | map PLUSASSIGN expr  { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::PLUS,  $3, @2)); }
                    | var PLUSASSIGN expr  { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::PLUS,  $3, @2)); }
                    | map MINUSASSIGN expr { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::MINUS, $3, @2)); }
                    | var MINUSASSIGN expr { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::MINUS, $3, @2)); }
                    | map MULASSIGN expr   { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::MUL,   $3, @2)); }
                    | var MULASSIGN expr   { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::MUL,   $3, @2)); }
                    | map DIVASSIGN expr   { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::DIV,   $3, @2)); }
                    | var DIVASSIGN expr   { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::DIV,   $3, @2)); }
                    | map MODASSIGN expr   { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::MOD,   $3, @2)); }
                    | var MODASSIGN expr   { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::MOD,   $3, @2)); }
                    | map BANDASSIGN expr  { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::BAND,  $3, @2)); }
                    | var BANDASSIGN expr  { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::BAND,  $3, @2)); }
                    | map BORASSIGN expr   { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::BOR,   $3, @2)); }
                    | var BORASSIGN expr   { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::BOR,   $3, @2)); }
                    | map BXORASSIGN expr  { $$ = std::make_unique<ast::AssignMapStatement>($1, std::make_unique<ast::Binop>($1, token::BXOR,  $3, @2)); }
                    | var BXORASSIGN expr  { $$ = std::make_unique<ast::AssignVarStatement>($1, std::make_unique<ast::Binop>($1, token::BXOR,  $3, @2)); }
                    ;

int : MINUS INT    { $$ = std::make_unique<ast::Integer>(-1 * $2, @$); }
    | INT          { $$ = std::make_unique<ast::Integer>($1, @$); }
    ;

expr : int                                      { $$ = std::move($1); }
     | STRING                                   { $$ = std::make_unique<ast::String>($1, @$); }
     | BUILTIN                                  { $$ = std::make_unique<ast::Builtin>($1, @$); }
     | CALL_BUILTIN                             { $$ = std::make_unique<ast::Builtin>($1, @$); }
     | IDENT                                    { $$ = std::make_unique<ast::Identifier>($1, @$); }
     | STACK_MODE                               { $$ = std::make_unique<ast::StackMode>($1, @$); }
     | ternary                                  { $$ = std::move($1); }
     | param                                    { $$ = std::move($1); }
     | map_or_var                               { $$ = std::move($1); }
     | call                                     { $$ = std::move($1); }
     | "(" expr ")"                             { $$ = std::move($2); }
     | expr EQ expr                             { $$ = std::make_unique<ast::Binop>(std::move($1), token::EQ, std::move($3), @2); }
     | expr NE expr                             { $$ = std::make_unique<ast::Binop>(std::move($1), token::NE, std::move($3), @2); }
     | expr LE expr                             { $$ = std::make_unique<ast::Binop>(std::move($1), token::LE, std::move($3), @2); }
     | expr GE expr                             { $$ = std::make_unique<ast::Binop>(std::move($1), token::GE, std::move($3), @2); }
     | expr LT expr                             { $$ = std::make_unique<ast::Binop>(std::move($1), token::LT, std::move($3), @2); }
     | expr GT expr                             { $$ = std::make_unique<ast::Binop>(std::move($1), token::GT, std::move($3), @2); }
     | expr LAND expr                           { $$ = std::make_unique<ast::Binop>(std::move($1), token::LAND,  std::move($3), @2); }
     | expr LOR expr                            { $$ = std::make_unique<ast::Binop>(std::move($1), token::LOR,   std::move($3), @2); }
     | expr LEFT expr                           { $$ = std::make_unique<ast::Binop>(std::move($1), token::LEFT,  std::move($3), @2); }
     | expr RIGHT expr                          { $$ = std::make_unique<ast::Binop>(std::move($1), token::RIGHT, std::move($3), @2); }
     | expr PLUS expr                           { $$ = std::make_unique<ast::Binop>(std::move($1), token::PLUS,  std::move($3), @2); }
     | expr MINUS expr                          { $$ = std::make_unique<ast::Binop>(std::move($1), token::MINUS, std::move($3), @2); }
     | expr MUL expr                            { $$ = std::make_unique<ast::Binop>(std::move($1), token::MUL,   std::move($3), @2); }
     | expr DIV expr                            { $$ = std::make_unique<ast::Binop>(std::move($1), token::DIV,   std::move($3), @2); }
     | expr MOD expr                            { $$ = std::make_unique<ast::Binop>(std::move($1), token::MOD,   std::move($3), @2); }
     | expr BAND expr                           { $$ = std::make_unique<ast::Binop>(std::move($1), token::BAND,  std::move($3), @2); }
     | expr BOR expr                            { $$ = std::make_unique<ast::Binop>(std::move($1), token::BOR,   std::move($3), @2); }
     | expr BXOR expr                           { $$ = std::make_unique<ast::Binop>(std::move($1), token::BXOR,  std::move($3), @2); }
     | LNOT expr                                { $$ = std::make_unique<ast::Unop>(token::LNOT, std::move($2), @1); }
     | BNOT expr                                { $$ = std::make_unique<ast::Unop>(token::BNOT, std::move($2), @1); }
     | MINUS expr                               { $$ = std::make_unique<ast::Unop>(token::MINUS, std::move($2), @1); }
     | MUL  expr %prec DEREF                    { $$ = std::make_unique<ast::Unop>(token::MUL,  std::move($2), @1); }
     | expr DOT ident                           { $$ = std::make_unique<ast::FieldAccess>(std::move($1), $3, @2); }
     | expr PTR ident                           { $$ = std::make_unique<ast::FieldAccess>(std::make_unique<ast::Unop>(token::MUL, std::move($1), @2), $3, @$); }
     | expr "[" expr "]"                        { $$ = std::make_unique<ast::ArrayAccess>(std::move($1), std::move($3), @2 + @4); }
     | "(" IDENT ")" expr %prec CAST            { $$ = std::make_unique<ast::Cast>($2, false, std::move($4), @1 + @3); }
     | "(" IDENT MUL ")" expr %prec CAST        { $$ = std::make_unique<ast::Cast>($2, true, std::move($5), @1 + @4); }
     | pre_post_op                              { $$ = std::move($1); }
     ;


pre_post_op : map_or_var INCREMENT   { $$ = std::make_unique<ast::Unop>(token::INCREMENT, $1, true, @2); }
            | map_or_var DECREMENT   { $$ = std::make_unique<ast::Unop>(token::DECREMENT, $1, true, @2); }
            | INCREMENT map_or_var   { $$ = std::make_unique<ast::Unop>(token::INCREMENT, $2, @1); }
            | DECREMENT map_or_var   { $$ = std::make_unique<ast::Unop>(token::DECREMENT, $2, @1); }
            | ident INCREMENT      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
            | INCREMENT ident      { error(@1, "The ++ operator must be applied to a map or variable"); YYERROR; }
            | ident DECREMENT      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
            | DECREMENT ident      { error(@1, "The -- operator must be applied to a map or variable"); YYERROR; }
            ;

ident : IDENT         { $$ = $1; }
      | BUILTIN       { $$ = $1; }
      | CALL          { $$ = $1; }
      | CALL_BUILTIN  { $$ = $1; }
      | STACK_MODE    { $$ = $1; }
      ;

call : CALL "(" ")"                 { $$ = std::make_unique<ast::Call>($1, @$); }
     | CALL "(" vargs ")"           { $$ = std::make_unique<ast::Call>($1, $3, @$); }
     | CALL_BUILTIN  "(" ")"        { $$ = std::make_unique<ast::Call>($1, @$); }
     | CALL_BUILTIN "(" vargs ")"   { $$ = std::make_unique<ast::Call>($1, $3, @$); }
     | IDENT "(" ")"                { error(@1, "Unknown function: " + $1); YYERROR;  }
     | IDENT "(" vargs ")"          { error(@1, "Unknown function: " + $1); YYERROR;  }
     | BUILTIN "(" ")"              { error(@1, "Unknown function: " + $1); YYERROR;  }
     | BUILTIN "(" vargs ")"        { error(@1, "Unknown function: " + $1); YYERROR;  }
     | STACK_MODE "(" ")"           { error(@1, "Unknown function: " + $1); YYERROR;  }
     | STACK_MODE "(" vargs ")"     { error(@1, "Unknown function: " + $1); YYERROR;  }
     ;

map : MAP               { $$ = std::make_unique<ast::Map>($1, @$); }
    | MAP "[" vargs "]" { $$ = std::make_unique<ast::Map>($1, $3, @$); }
    ;

var : VAR { $$ = std::make_unique<ast::Variable>($1, @$); }
    ;

map_or_var : var { $$ = std::move($1); }
           | map { $$ = std::move($1); }
           ;

vargs : vargs "," expr { $$ = std::move($1); $$->push_back($3); }
      | expr           { $$ = std::make_unique<ast::ExpressionList>(); $$->push_back(std::move($1)); }
      ;

%%

void bpftrace::Parser::error(const location &l, const std::string &m)
{
  driver.error(l, m);
}
