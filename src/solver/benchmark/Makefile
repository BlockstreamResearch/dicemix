impl = flint

src_flint = ../solver_flint.cpp
obj_flint = $(src:.cpp=.o)

CPPFLAGS = -DSTANDALONE -O3
LDFLAGS_flint = -lflint -lgmp

output/solver: output $(obj)
	$(CXX) $(CPPFLAGS) -o output/solver $(src_$(impl)) $(LDFLAGS_$(impl))

output:
	mkdir -p output

.PHONY: clean
clean:
	rm -f $(obj) output/solver
