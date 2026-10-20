import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from graphql import build_schema, graphql_sync

schema = build_schema("""
    type User {
        id: ID!
        name: String!
        email: String!
    }

    type Note {
        id: ID!
        text: String!
    }

    type Query {
        health: String!
        users: [User!]!
        user(id: ID!): User
    }

    type Mutation {
        createNote(text: String!): Note!
    }
""")

users = [
    {"id": "1", "name": "Test Alice", "email": "alice@example.test"},
    {"id": "2", "name": "Test Bob", "email": "bob@example.test"},
]

schema.query_type.fields["health"].resolve = lambda *_: "ok"
schema.query_type.fields["users"].resolve = lambda *_: users
schema.query_type.fields["user"].resolve = lambda _root, _info, id: next(
    (u for u in users if u["id"] == id), None
)
schema.mutation_type.fields["createNote"].resolve = lambda _root, _info, text: {
    "id": "test-note",
    "text": text,
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/graphql":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            result = graphql_sync(
                schema,
                payload.get("query", ""),
                variable_values=payload.get("variables"),
                operation_name=payload.get("operationName"),
            )
            body = json.dumps(result.formatted).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ValueError, TypeError, json.JSONDecodeError):
            self.send_error(400, "Invalid JSON request")

    def log_message(self, fmt, *args):
        print(f"[LOCAL LAB] {fmt % args}")


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8765), Handler)
    print("Local GraphQL lab: http://127.0.0.1:8765/graphql")
    print("Health check:      http://127.0.0.1:8765/health")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local lab...")
    finally:
        server.server_close()
