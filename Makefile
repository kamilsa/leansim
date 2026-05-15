SCENARIO ?= experiments/geo-128.toml
NETVIZ_OUT ?= netviz-trace.bctrace

.PHONY: docker-build docker-run docker-netviz

docker-build:
	docker build --platform linux/arm64 -f Dockerfile.build -t leansim-builder .
	docker create --name leansim-tmp leansim-builder
	mkdir -p target/release
	docker cp leansim-tmp:/app/target/release/leansim target/release/leansim
	docker rm leansim-tmp

docker-run:
	docker compose run --rm leansim "$(SCENARIO)"

docker-netviz:
	docker compose run --rm --entrypoint /root/leansim/target/release/leansim leansim netviz \
		--experiment "/root/leansim/$(SCENARIO)" \
		--shadow-data /mnt/output/shadow.data \
		--out "/mnt/output/$(NETVIZ_OUT)"
