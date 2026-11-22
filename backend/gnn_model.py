import torch
import torch.nn.functional as F

from torch_geometric.nn import GCNConv


class ZeroGuardGNN(torch.nn.Module):

    def __init__(
        self,
        input_features=2,
        hidden_features=16,
        output_features=2
    ):
        super().__init__()

        self.conv1 = GCNConv(
            input_features,
            hidden_features
        )

        self.conv2 = GCNConv(
            hidden_features,
            output_features
        )

    def forward(self, x, edge_index):

        x = self.conv1(
            x,
            edge_index
        )

        x = F.relu(x)

        x = F.dropout(
            x,
            p=0.2,
            training=self.training
        )

        x = self.conv2(
            x,
            edge_index
        )

        return x


if __name__ == "__main__":

    print()
    print("========================================")
    print(" ZeroGuard Graph Neural Network")
    print("========================================")

    model = ZeroGuardGNN()

    print()
    print(model)

    print()
    print("GNN model created successfully.")