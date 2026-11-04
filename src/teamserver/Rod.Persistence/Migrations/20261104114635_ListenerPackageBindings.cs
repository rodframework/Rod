using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Rod.Persistence.Migrations
{
    /// <summary>
    /// Package-backed listener bindings (ADR-025): the package a listener
    /// resolves (name, version, seal tier) and the medium parameters its
    /// restart respawns with. The transport column widens to hold a
    /// package's own name, where a package-backed row stores it.
    /// </summary>
    public partial class ListenerPackageBindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "transport",
                table: "listener_definitions",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(32)",
                oldMaxLength: 32);

            migrationBuilder.AddColumn<string>(
                name: "package_name",
                table: "listener_definitions",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "package_version",
                table: "listener_definitions",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "params_json",
                table: "listener_definitions",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "seal_tier",
                table: "listener_definitions",
                type: "character varying(16)",
                maxLength: 16,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "package_name",
                table: "listener_definitions");

            migrationBuilder.DropColumn(
                name: "package_version",
                table: "listener_definitions");

            migrationBuilder.DropColumn(
                name: "params_json",
                table: "listener_definitions");

            migrationBuilder.DropColumn(
                name: "seal_tier",
                table: "listener_definitions");

            migrationBuilder.AlterColumn<string>(
                name: "transport",
                table: "listener_definitions",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(128)",
                oldMaxLength: 128);
        }
    }
}
