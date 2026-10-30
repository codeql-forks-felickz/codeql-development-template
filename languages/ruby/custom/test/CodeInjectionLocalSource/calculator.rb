#!/usr/bin/ruby
# Synthetic command-line calculator that evaluates its arguments as Ruby code.

puts "Calculating"
first_number  = ARGV[0] # $ Source
second_number = ARGV[1] # $ Source
print "Args:", first_number, second_number, "\n"
print eval(first_number + "+" + second_number) # $ Alert

# Whole argument evaluated directly.
eval(ARGV.first) # $ Alert

# Value read from stdin evaluated as code.
expr = STDIN.gets # $ Source
instance_eval(expr) # $ Alert

line = $stdin.read # $ Source
Object.class_eval(line) # $ Alert

input = gets # $ Source
eval(input) # $ Alert

# Safe: arguments are converted to integers before being evaluated.
a = ARGV[0].to_i
b = ARGV[1].to_i
print eval("#{a} + #{b}")

# Safe: argument is checked against an allow list before being evaluated.
op = ARGV[2]
if op == "+" || op == "-"
  print eval("1 #{op} 2")
end

# Safe: arguments are only printed, never evaluated.
puts ARGV.join(" ")

# Safe: constant code is evaluated.
eval("1 + 2")

# Safe: `const_get` only loads a constant, so it is a sink only when the attacker
# controls the entire string, which the concatenation prevents.
Object.const_get("Kernel" + ARGV[3])
