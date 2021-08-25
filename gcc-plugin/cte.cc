#include <string>
#include <vector>
#include <set>
#include <gcc-plugin.h>
#include <plugin-version.h>
#include <intl.h>
#include <diagnostic.h>
#include <tree.h>
#include <stor-layout.h>
#include <cgraph.h>
#include <langhooks.h>
#include <stringpool.h>

int plugin_is_GPL_compatible;

struct plugin_info mv_plugin_info = {
    .version = "0",
    .help = "dump the call graph\n"
};


#define RECORD_FIELD(type)                                       \
    field = build_decl(BUILTINS_LOCATION, FIELD_DECL, NULL_TREE, \
                       (type)); \
    DECL_CHAIN(field) = fields; \
    fields = field;

static tree build_info_fn_type()
{
    /*
     * struct __cte_info_fn {
     *   void *fn;
     *   void *fn_end;
     *   int flags;
     *   int calles_count;
     *   void **callees;
     * };
     */

    tree info_fn_type = lang_hooks.types.make_type(RECORD_TYPE);
    tree field, fields = NULL_TREE;

    // fn
    RECORD_FIELD(build_pointer_type(void_type_node));

    // fn_end
    RECORD_FIELD(build_pointer_type(void_type_node));

    // flags
    RECORD_FIELD(integer_type_node);

    // callees_count
    RECORD_FIELD(integer_type_node);

    // callees
    tree ptr = build_pointer_type(build_pointer_type(void_type_node));
    RECORD_FIELD(build_qualified_type(ptr, TYPE_QUAL_CONST));

    finish_builtin_struct(info_fn_type, "__cte_info_fn", fields, NULL_TREE);
    TYPE_PACKED(info_fn_type) = 1;
    return info_fn_type;
}

static tree build_info_fn(tree type, cgraph_node *node, std::set<tree> callees) {
    tree ptrtype = build_pointer_type(void_type_node);

    vec<constructor_elt, va_gc> *obj = NULL;
    tree info_fields = TYPE_FIELDS(type);

    // fn (function address) as a (void *)
    CONSTRUCTOR_APPEND_ELT(obj, info_fields, build1(ADDR_EXPR, ptrtype, node->decl));
    info_fields = DECL_CHAIN(info_fields);

    // fn_end (function end address) as a (void *)
    std::string lab_name = std::string(".LFE") + std::to_string(node->get_fun()->funcdef_no);
    tree lab = build_decl(BUILTINS_LOCATION, VAR_DECL, NULL_TREE, ptrtype);
    DECL_EXTERNAL(lab) = 1;
    TREE_STATIC(lab) = 1;
    SET_DECL_ASSEMBLER_NAME(lab, get_identifier(lab_name.c_str()));
    CONSTRUCTOR_APPEND_ELT(obj, info_fields, build1(ADDR_EXPR, ptrtype, lab));
    info_fields = DECL_CHAIN(info_fields);

    // flags as int
    int flags = node->address_taken;
    CONSTRUCTOR_APPEND_ELT(obj, info_fields,
                           build_int_cst(TREE_TYPE(info_fields), flags));
    info_fields = DECL_CHAIN(info_fields);

    // calles_count as int
    CONSTRUCTOR_APPEND_ELT(obj, info_fields,
                           build_int_cst(TREE_TYPE(info_fields), callees.size()));
    info_fields = DECL_CHAIN(info_fields);

    // callees
    auto array_name = std::string("__cte_callees_") +
        IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(node->decl));
    vec<constructor_elt, va_gc> *array_ctor = NULL;
    if (!callees.empty()) {
        for (auto &callee : callees) {
            tree c = build1(ADDR_EXPR, ptrtype, callee);
            CONSTRUCTOR_APPEND_ELT(array_ctor, NULL, c);
        }
        tree qtype = build_qualified_type(ptrtype, TYPE_QUAL_CONST);
        tree itype = build_index_type(size_int(callees.size() - 1));
        tree array_type = build_array_type(qtype, itype);
        tree array = build_decl(BUILTINS_LOCATION, VAR_DECL, NULL_TREE, array_type);
        SET_DECL_ASSEMBLER_NAME(array, get_identifier(array_name.c_str()));
        TREE_STATIC(array) = 1;
        TREE_ADDRESSABLE(array) = 1;
        DECL_NONALIASED(array) = 1;
        DECL_VISIBILITY_SPECIFIED(array) = 1;
        DECL_VISIBILITY(array) = VISIBILITY_HIDDEN;
        DECL_INITIAL(array) = build_constructor(array_type, array_ctor);
        set_decl_section_name(array, "__cte_data_");
        varpool_node::finalize_decl(array);

        tree array_ptrtype = build_pointer_type(build_pointer_type(void_type_node));
        CONSTRUCTOR_APPEND_ELT(obj, info_fields, build1(ADDR_EXPR, array_ptrtype, array));
    } else {
        CONSTRUCTOR_APPEND_ELT(obj, info_fields,
                               build_int_cstu(TREE_TYPE(info_fields), 0));
    }
    info_fields = DECL_CHAIN(info_fields);

    gcc_assert(!info_fields); // All fields are filled
    return build_constructor(type, obj);
}

static void build_section_array(std::vector<tree> fns, tree info_fn_type) {
    vec<constructor_elt, va_gc> *array_ctor = NULL;
    for (auto &fn : fns) {
        CONSTRUCTOR_APPEND_ELT(array_ctor, NULL, fn);
    }
    tree qtype = build_qualified_type(info_fn_type, TYPE_QUAL_CONST);
    tree itype = build_index_type(size_int(fns.size() - 1));
    tree array_type = build_array_type(qtype, itype);
    tree array = build_decl(BUILTINS_LOCATION, VAR_DECL, NULL_TREE, array_type);
    SET_DECL_ASSEMBLER_NAME(array, get_identifier("__cte_fn_local"));
    TREE_STATIC(array) = 1;
    TREE_ADDRESSABLE(array) = 1;
    DECL_NONALIASED(array) = 1;
    DECL_VISIBILITY_SPECIFIED(array) = 1;
    DECL_VISIBILITY(array) = VISIBILITY_HIDDEN;
    DECL_INITIAL(array) = build_constructor(array_type, array_ctor);

    // Set the smallest possible alignment.  The sections of all compilation
    // units will be merged during linking and will be accessed as a single
    // array by the runtime library.
    SET_DECL_ALIGN(array, 0);
    DECL_USER_ALIGN(array) = 1;

    // Let the linker not throw away the array (__attribute__((used)))
    DECL_PRESERVE_P(array) = 1;

    set_decl_section_name(array, "__cte_fn_");
    varpool_node::finalize_decl(array);
}

static void collect_info(void*, void*) {
    tree info_fn_type = build_info_fn_type();
    std::vector<tree> fns;

    cgraph_node *node;
    FOR_EACH_FUNCTION(node) {
        // Only consider function definitions
        if (!node->definition)
            continue;

        std::set<tree> callees;
        for (cgraph_edge *edge = node->callees; edge; edge = edge->next_callee) {
            callees.insert(edge->callee->decl);
        }
        tree fn = build_info_fn(info_fn_type, node, callees);
        fns.push_back(fn);
    }

    build_section_array(fns, info_fn_type);
}

int plugin_init(struct plugin_name_args *info, struct plugin_gcc_version *version) {
    const char * plugin_name = info->base_name;

    // struct register_pass_info textviu_callsites_info;

    if (!plugin_default_version_check(version, &gcc_version)) {
        error(G_("incompatible gcc/plugin versions"));
        return 1;
    }

    register_callback(plugin_name, PLUGIN_ALL_IPA_PASSES_END, collect_info, NULL);
    return 0;
}
