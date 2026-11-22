import torch
from torch_geometric.data import Data

from graph_builder import build_network_graph


def create_gnn_data():

    graph = build_network_graph()

    if graph.number_of_nodes() == 0:

        print("No network graph data available.")

        return None

    # --------------------------------------------------------
    # Give every IP/node a numerical ID
    # --------------------------------------------------------

    nodes = list(graph.nodes())

    node_to_id = {
        node: index
        for index, node in enumerate(nodes)
    }

    # --------------------------------------------------------
    # Create edges
    # --------------------------------------------------------

    edge_list = []

    for source, destination in graph.edges():

        source_id = node_to_id[source]
        destination_id = node_to_id[destination]

        edge_list.append(
            [source_id, destination_id]
        )

        edge_list.append(
            [destination_id, source_id]
        )

    edge_index = torch.tensor(
        edge_list,
        dtype=torch.long
    ).t().contiguous()

    # --------------------------------------------------------
    # Create node features
    # --------------------------------------------------------

    node_features = []

    for node in nodes:

        degree = graph.degree(node)

        connections = 0

        for neighbor in graph.neighbors(node):

            connections += graph[node][neighbor].get(
                "connection_count",
                1
            )

        node_features.append(
            [
                float(degree),
                float(connections),
            ]
        )

    x = torch.tensor(
        node_features,
        dtype=torch.float
    )

    # --------------------------------------------------------
    # Create PyTorch Geometric Data object
    # --------------------------------------------------------

    data = Data(
        x=x,
        edge_index=edge_index
    )

    return data, nodes


if __name__ == "__main__":

    print()
    print("========================================")
    print(" ZeroGuard GNN Data Preparation")
    print("========================================")

    result = create_gnn_data()

    if result is not None:

        data, nodes = result

        print()
        print("GNN Data Created")
        print("----------------")
        print(f"Number of nodes: {data.num_nodes}")
        print(f"Number of edges: {data.num_edges}")
        print(f"Node feature size: {data.num_node_features}")

        print()
        print("Node mapping:")

        for index, node in enumerate(nodes):

            print(f"{index} → {node}")

        print()
        print("Node features:")
        print(data.x)

        print()
        print("Edge index:")
        print(data.edge_index)

        print()
        print("GNN data preparation successful.")