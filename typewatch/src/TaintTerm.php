<?php
/**
 * A "term" is the abstract summary of an expression's value as taint analysis sees it.
 * Flow-insensitive may-analysis: merging two terms keeps taint if either is tainted.
 */
final class TaintTerm {
    public bool $tainted = false;
    /** @var string[] human-readable source labels, e.g. '$_GET["password"]' */
    public array $sources = [];
    /** Last superglobal parameter key when derivable, e.g. 'password' */
    public ?string $paramKey = null;
    /** Ordered transforms: [['op'=>'md5','line'=>12,'desc'=>'md5(...)'], ...] */
    public array $transforms = [];
    /** Variables this term flowed through, e.g. ['$user','$hash'] */
    public array $vars = [];
    /** Set when the expression is a compile-time literal */
    public ?array $literal = null;
    /** Inferred type constraints: 'int','float','string','bool','array','null','mixed' */
    public array $types = [];
    /** True for function-parameter placeholder terms before instantiation */
    public bool $isParam = false;
    public int $paramIndex = -1;

    public static function clean(array $types = []): self {
        $t = new self();
        $t->types = $types;
        return $t;
    }

    public static function literal(array $node): self {
        $t = new self();
        $t->literal = $node;
        $t->types = [self::nodeType($node)];
        return $t;
    }

    public static function source(string $label, ?string $key, array $types = ['string', 'array']): self {
        $t = new self();
        $t->tainted = true;
        $t->sources = [$label];
        $t->paramKey = $key;
        $t->types = $types;
        return $t;
    }

    public static function param(int $index, string $name): self {
        $t = new self();
        $t->tainted = true;
        $t->isParam = true;
        $t->paramIndex = $index;
        $t->sources = ["param:\${$name}"];
        $t->vars = ["\${$name}"];
        $t->types = ['mixed'];
        return $t;
    }

    public static function unknown(array $types = ['mixed']): self {
        $t = new self();
        $t->types = $types;
        return $t;
    }

    public static function nodeType(array $node): string {
        return match ($node['kind'] ?? '') {
            'int' => 'int',
            'float' => 'float',
            'string', 'dstring' => 'string',
            'bool' => 'bool',
            'null' => 'null',
            'array' => 'array',
            default => 'mixed',
        };
    }

    public function withTransform(string $op, ?int $line, string $desc = ''): self {
        $c = clone $this;
        $c->transforms[] = ['op' => $op, 'line' => $line, 'desc' => $desc ?: $op];
        return $c;
    }

    public function addVar(string $name): self {
        $c = clone $this;
        if (!in_array($name, $c->vars, true)) $c->vars[] = $name;
        return $c;
    }

    public function setTypes(array $types): self {
        $c = clone $this;
        $c->types = $types;
        return $c;
    }

    /**
     * Merge two may-aliased terms (different assignments to the same variable).
     */
    public static function merge(self $a, self $b): self {
        $m = new self();
        $m->tainted = $a->tainted || $b->tainted;
        $m->sources = array_values(array_unique(array_merge($a->sources, $b->sources)));
        $m->paramKey = $a->paramKey ?? $b->paramKey;
        $m->vars = array_values(array_unique(array_merge($a->vars, $b->vars)));
        $m->transforms = array_merge($a->transforms, $b->transforms);
        $m->types = array_values(array_unique(array_merge($a->types, $b->types)));
        // Literal survives only when both agree.
        if ($a->literal !== null && $b->literal !== null && json_encode($a->literal) === json_encode($b->literal)) {
            $m->literal = $a->literal;
        }
        return $m;
    }

    public function toArray(): array {
        return [
            'tainted' => $this->tainted,
            'sources' => $this->sources,
            'paramKey' => $this->paramKey,
            'transforms' => $this->transforms,
            'vars' => $this->vars,
            'literal' => $this->literal,
            'types' => $this->types,
        ];
    }

    /** Last transform op, useful for the version engine (e.g. 'md5'). */
    public function lastTransform(): ?string {
        if (!$this->transforms) return null;
        return $this->transforms[array_key_last($this->transforms)]['op'];
    }

    public function hasTransform(string $op): bool {
        foreach ($this->transforms as $tr) if ($tr['op'] === $op) return true;
        return false;
    }
}

final class FuncSummary {
    public function __construct(
        public string $name,
        public array $paramNames,
        public ?array $body,
        public int $line,
        public bool $static = false,
        public string $className = '',
    ) {}
}
