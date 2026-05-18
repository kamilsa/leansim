SCENARIO ?= experiments/local-64.toml
OUTPUT_DIR ?= output
NETVIZ_OUT ?= netviz-trace.bctrace
PARALLELISM ?= 0

.PHONY: build run netviz docker-build docker-run docker-netviz

build:
	cargo build --release

run: build
	mkdir -p "$(OUTPUT_DIR)"
	./target/release/leansim gen-shadow \
		--experiment "$(SCENARIO)" \
		--out "$(OUTPUT_DIR)/shadow.yaml"
	rm -rf "$(OUTPUT_DIR)/shadow.data"
	cd "$(OUTPUT_DIR)" && shadow --progress true --parallelism "$(PARALLELISM)" shadow.yaml

netviz:
	./target/release/leansim netviz \
		--experiment "$(SCENARIO)" \
		--shadow-data "$(OUTPUT_DIR)/shadow.data" \
		--out "$(NETVIZ_OUT)"

docker-build:
	docker build --platform linux/arm64 -f Dockerfile.build -t leansim-builder .
	docker create --name leansim-tmp leansim-builder
	mkdir -p target/release
	docker cp leansim-tmp:/app/target/release/leansim target/release/leansim
	docker rm leansim-tmp

docker-run:
	docker compose run --rm -e SHADOW_FLAGS="--progress true --parallelism $(PARALLELISM)" leansim "$(SCENARIO)"

docker-netviz:
	docker compose run --rm --entrypoint /root/leansim/target/release/leansim leansim netviz \
		--experiment "/root/leansim/$(SCENARIO)" \
		--shadow-data /mnt/output/shadow.data \
		--out "/mnt/output/$(NETVIZ_OUT)"
