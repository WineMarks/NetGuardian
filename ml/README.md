# NetGuardian ML

阶段一的模型训练与预测代码。

## 目标
- 读取 `MachineLearningCVE/` 下的 CIC 风格 CSV 数据
- 做基础清洗、归一化和标签编码
- 训练多分类模型并保存 artifact
- 提供单条流量 JSON 的预测接口

## 运行
```bash
/home/meta/miniconda3/envs/cqy/bin/python ml/scripts/train.py --data-dir MachineLearningCVE
```

默认使用 `sklearn` 后端（`SGDClassifier + 预处理 Pipeline`）。

切换为 PyTorch 深度学习后端：
```bash
/home/meta/miniconda3/envs/cqy/bin/python ml/scripts/train.py --data-dir MachineLearningCVE --model-type pytorch
```

切换为 TabNet 后端（`pytorch_tabnet`）：
```bash
/home/meta/miniconda3/envs/cqy/bin/python ml/scripts/train.py --data-dir MachineLearningCVE --model-type tabnet
```

3090 建议参数（class_weight + 全量 + 进度条）：
```bash
/home/meta/miniconda3/envs/cqy/bin/python ml/scripts/train.py \
	--data-dir MachineLearningCVE \
	--model-type tabnet \
	--imbalance-strategy class_weight \
	--sample-per-file 0 \
	--batch-size 8192 \
	--virtual-batch-size 1024 \
	--num-workers 8 \
	--max-epochs 20 \
	--patience 10
```

训练过程中会显示 TabNet epoch 进度条和指标后缀日志。

三种后端都产出同一种 artifact 结构，并通过同一个 `FlowPredictor` 对上层暴露预测接口。

## 样本与不均衡策略
- `--sample-per-file` 控制每个 CSV 采样上限。
- 设为 `0` 表示不做采样上限（尽可能使用每个文件的全部可用行）。
- `--imbalance-strategy` 支持：
	- `none`: 不做额外类别不均衡处理。
	- `class_weight`: 使用类别权重。
	- `focal`: 使用 Focal Loss（深度学习后端）或等效类别权重策略（sklearn）。
